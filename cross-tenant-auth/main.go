package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
)

var (
	msi                 string
	tenantID            string
	subscriptionID      string
	vmssResourceID      ResourceID
	netTenantID         string
	netSubscriptionID   string
	vnetResourceID      ResourceID
	auxTokenKeyVaultURL string
	auxToken            string
)

type ResourceID struct {
	SubscriptionID string
	ResourceGroup  string
	Provider       string
	ResourceName   string
}

func (r ResourceID) String() string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/%s/%s", r.SubscriptionID, r.ResourceGroup, r.Provider, r.ResourceName)
}

type AuxTokenCredential struct {
	auxTokenKeyVaultURL string
}

func NewAuxTokenCredential(auxTokenKeyVaultURL string) (*AuxTokenCredential, error) {
	return &AuxTokenCredential{
		auxTokenKeyVaultURL: auxTokenKeyVaultURL,
	}, nil
}

func (c *AuxTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	token := azcore.AccessToken{}
	token.ExpiresOn.After(time.Now())
	if auxToken != "" {
		log.Printf("Returning pre-configured aux token: len=%d", len(auxToken))
		return azcore.AccessToken{
			Token:     auxToken,
			ExpiresOn: time.Now().Add(time.Hour),
		}, nil
	}
	return azcore.AccessToken{}, nil
}

type Credential struct {
	msiCredential      *azidentity.ManagedIdentityCredential
	auxTokenCredential *AuxTokenCredential
}

func NewCredential(auxTokenCredential *AuxTokenCredential) (*Credential, error) {
	msiCredential, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ID: azidentity.ClientID(msi),
	})
	if err != nil {
		log.Printf("Failed to setup ManagedIdentity Crendential: %s", err)
		return nil, fmt.Errorf("setup ManagedIdentity Crendential: %w", err)
	}

	return &Credential{
		msiCredential:      msiCredential,
		auxTokenCredential: auxTokenCredential,
	}, nil
}

func (c *Credential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	log.Printf("Getting token from tenant: %s", opts.TenantID)

	var (
		token azcore.AccessToken
		err   error
	)
	switch opts.TenantID {
	case netTenantID:
		token, err = c.auxTokenCredential.GetToken(ctx, opts)
	default:
		token, err = c.msiCredential.GetToken(ctx, opts)
	}
	if err != nil {
		log.Printf("Failed to get token: %s", err)
		return token, fmt.Errorf("get token: %w", err)
	}
	log.Printf("Returning token: %s", token.Token)
	return token, nil
}

func main() {
	flag.StringVar(&msi, "msi", "", "The MSI")
	flag.StringVar(&tenantID, "tenant-id", "", "The Tenant ID")
	flag.StringVar(&subscriptionID, "subscription-id", "", "The Subscription ID")
	flag.StringVar(&vmssResourceID.ResourceGroup, "vmss-resource-group", "", "The VMSS Resource Group")
	flag.StringVar(&vmssResourceID.ResourceName, "vmss-resource-name", "", "The VMSS Resource Name")
	flag.StringVar(&netTenantID, "net-tenant-id", "", "The network Tenant ID")
	flag.StringVar(&netSubscriptionID, "net-subscription-id", "", "The network Subscription ID")
	flag.StringVar(&vnetResourceID.ResourceGroup, "vnet-resource-group", "", "The VNet Resource Group")
	flag.StringVar(&vnetResourceID.ResourceName, "vnet-resource-name", "", "The VNet Resource Name")
	flag.StringVar(&auxTokenKeyVaultURL, "aux-token-key-vault-url", "", "The KeyVault URL for the aux token")
	flag.StringVar(&auxToken, "aux-token", "", "The aux token")
	flag.Parse()

	log.Printf("Aux Token: %s", auxToken)

	vmssResourceID.Provider = "Microsoft.Compute/virtualMachineScaleSets"
	vmssResourceID.SubscriptionID = subscriptionID
	vnetResourceID.Provider = "Microsoft.Network/virtualNetworks"
	vnetResourceID.SubscriptionID = netSubscriptionID

	netCredential, err := NewAuxTokenCredential(auxTokenKeyVaultURL)
	if err != nil {
		log.Fatalf("Failed to setup AuxTokenCredential: %s", err)
	}

	cred, err := NewCredential(netCredential)
	if err != nil {
		log.Fatalf("Failed to setup Credential: %s", err)
	}

	computeClientFactory, err := armcompute.NewClientFactory(subscriptionID, cred, &arm.ClientOptions{
		AuxiliaryTenants: []string{netTenantID},
	})
	if err != nil {
		log.Fatalf("Failed to setup ComputeClientFactory: %s", err)
	}
	networkClientFactory, err := armnetwork.NewClientFactory(netSubscriptionID, netCredential, nil)
	if err != nil {
		log.Fatalf("Failed to setup NetworkClientFactory: %s", err)
	}

	ctx := context.Background()

	log.Printf("Creating VirtualNetwork: %s", vnetResourceID)
	vnet, err := CreateVNet(ctx, networkClientFactory, vnetResourceID)
	if err != nil {
		log.Fatalf("Failed to create VNet: %s", err)
	}
	{
		log.Printf("Created VirtualNetwork")
		encoded, _ := json.Marshal(vnet)
		log.Printf("VNet: %s", string(encoded))
	}

	log.Printf("Creating VMSS: %s", vmssResourceID)
	vmss, err := CreateVMSS(ctx, computeClientFactory, vmssResourceID, vnet)
	if err != nil {
		log.Fatalf("Failed to create VMSS: %s", err)
	}
	{
		log.Printf("Created VMSS")
		encoded, _ := json.Marshal(vmss)
		log.Printf("VMSS: %s", string(encoded))
	}
}

func CreateVMSS(ctx context.Context, factory *armcompute.ClientFactory, vmssID ResourceID, vnet *armnetwork.VirtualNetwork) (*armcompute.VirtualMachineScaleSet, error) {
	cli := factory.NewVirtualMachineScaleSetsClient()
	{
		// Clean up
		poller, err := cli.BeginDelete(ctx, vmssID.ResourceGroup, vmssID.ResourceName, nil)
		if err != nil {
			return nil, fmt.Errorf("createVMSS: beginDelete: %w", err)
		}
		_, _ = poller.PollUntilDone(ctx, nil) // ignore error
	}

	// Create
	poller, err := cli.BeginCreateOrUpdate(ctx, vmssID.ResourceGroup, vmssID.ResourceName, armcompute.VirtualMachineScaleSet{
		Location: to.Ptr("eastus"),
		Properties: &armcompute.VirtualMachineScaleSetProperties{
			Overprovision: to.Ptr(false),
			UpgradePolicy: &armcompute.UpgradePolicy{
				Mode: to.Ptr(armcompute.UpgradeModeManual),
				AutomaticOSUpgradePolicy: &armcompute.AutomaticOSUpgradePolicy{
					EnableAutomaticOSUpgrade: to.Ptr(false),
					DisableAutomaticRollback: to.Ptr(false),
				},
			},
			VirtualMachineProfile: &armcompute.VirtualMachineScaleSetVMProfile{
				OSProfile: &armcompute.VirtualMachineScaleSetOSProfile{
					ComputerNamePrefix: to.Ptr("vmss"),
					AdminUsername:      to.Ptr("sample-user"),
					AdminPassword:      to.Ptr("Password01!@#"),
				},
				StorageProfile: &armcompute.VirtualMachineScaleSetStorageProfile{
					ImageReference: &armcompute.ImageReference{
						Publisher: to.Ptr("Canonical"),
						Offer:     to.Ptr("0001-com-ubuntu-server-jammy"),
						SKU:       to.Ptr("22_04-lts-gen2"),
						Version:   to.Ptr("latest"),
					},
				},
				NetworkProfile: &armcompute.VirtualMachineScaleSetNetworkProfile{
					NetworkInterfaceConfigurations: []*armcompute.VirtualMachineScaleSetNetworkConfiguration{
						{
							Name: to.Ptr("default"),
							Properties: &armcompute.VirtualMachineScaleSetNetworkConfigurationProperties{
								Primary: to.Ptr(true),
								IPConfigurations: []*armcompute.VirtualMachineScaleSetIPConfiguration{
									{
										Name: to.Ptr("ipconfig1"),
										Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{
											Primary: to.Ptr(true),
											Subnet: &armcompute.APIEntityReference{
												ID: vnet.Properties.Subnets[0].ID,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		SKU: &armcompute.SKU{
			Name:     to.Ptr("Standard_B2s"),
			Tier:     to.Ptr("Standard"),
			Capacity: to.Ptr(int64(3)),
		},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("createVMSS: beginCreateOrUpdate: %w", err)
	}

	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("createVMSS: pollUntilDone: %w", err)
	}

	return &resp.VirtualMachineScaleSet, nil
}

func CreateVNet(ctx context.Context, factory *armnetwork.ClientFactory, vnetID ResourceID) (*armnetwork.VirtualNetwork, error) {
	cli := factory.NewVirtualNetworksClient()
	poller, err := cli.BeginCreateOrUpdate(ctx, vnetID.ResourceGroup, vnetID.ResourceName, armnetwork.VirtualNetwork{
		Location: to.Ptr("eastus"),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{
					to.Ptr("172.26.0.0/16"),
				},
			},
			Subnets: []*armnetwork.Subnet{
				{
					Name: to.Ptr("default"),
					Properties: &armnetwork.SubnetPropertiesFormat{
						AddressPrefix: to.Ptr("172.26.0.0/24"),
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("createVNet: beginCreateOrUpdate: %w", err)
	}
	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("createVNet: pollUntilDone: %w", err)
	}

	return &resp.VirtualNetwork, nil
}

func runLoop() {
	for {
		next := time.Now().Add(time.Minute)
		time.Sleep(time.Until(next))

	}
}
