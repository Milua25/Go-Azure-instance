package main

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/wardviaene/golang-for-devops-course/ssh-demo"
	"log"
	"os"
)

const (
	location             = "Canada Central"
	virtualNetworkName   = "test-vnet"
	subnetName           = "test-subnet"
	publicIpName         = "test-ip"
	securityGroupName    = "test-nsg"
	networkInterfaceName = "test-nic"
	diskName             = "test-disk"
	vmName               = "test-vm"
	resourceGroupName    = "test-azure-sdk-rg"
)

var (
	token         *azidentity.AzureCLICredential
	privateKey    string
	pubKey        string
	err           error
	clientFactory *armresources.ClientFactory

	virtualNetworksClient *armnetwork.VirtualNetworksClient
	subnetsClient         *armnetwork.SubnetsClient
	securityGroupsClient  *armnetwork.SecurityGroupsClient
	networkClientFactory  *armnetwork.ClientFactory
	ipClient              *armnetwork.PublicIPAddressesClient
	nicInterface          *armnetwork.InterfacesClient

	computeClientFactory  *armcompute.ClientFactory
	virtualMachinesClient *armcompute.VirtualMachinesClient
	disksClient           *armcompute.DisksClient
)

func main() {
	fmt.Println("Launching an azure virtual machine")

	ctx := context.Background()

	subscriptionID := os.Getenv("SUBSCRIPTION_ID")
	if len(subscriptionID) == 0 {
		log.Println("No Subscription id was provided")
		os.Exit(1)
	}

	if pubKey, privateKey, err = generateKeys(); err != nil {
		log.Printf("generate keys error: %s\n", err)
		os.Exit(1)
	}

	if token, err = getToken(); err != nil {
		log.Printf("Could not generate token: %s\n", err)
		os.Exit(1)
	}
	keepResource := os.Getenv("KEEP_RESOURCE")
	fmt.Println(keepResource)

	//if err = launchInstance(ctx, virtualNetworkName, subnetName, publicIpName, securityGroupName, networkInterfaceName, location, resourceGroupName, subscriptionID, pubKey, token); err != nil {
	//	log.Printf("Could not launch a VM instance: %s\n", err)
	//	os.Exit(1)
	//}

	if len(keepResource) == 0 {
		//delete virtual machine
		cleanup(ctx)
	}
}

func generateKeys() (string, string, error) {
	var (
		privateKey []byte
		publicKey  []byte
		err        error
	)

	if privateKey, publicKey, err = ssh.GenerateKeys(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	if err = os.WriteFile("myKey.pem", privateKey, 0666); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	if err = os.WriteFile("myKey.pub", publicKey, 0666); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	return string(publicKey), string(privateKey), nil
}

func getToken() (*azidentity.AzureCLICredential, error) {
	azCLI, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		return nil, err
	}
	//	azCLI.GetToken()
	return azCLI, nil
}

func launchInstance(ctx context.Context, vnetName, subnetName, publicIpName, sgName, nicName, location, rgName, subId, pubKey string, token *azidentity.AzureCLICredential) error {

	clientFactory, err = armresources.NewClientFactory(subId, token, nil)
	if err != nil {
		return fmt.Errorf("failed to create client: %v\n", err)
	}

	newResourceGroupsResponse, err := clientFactory.NewResourceGroupsClient().CreateOrUpdate(
		ctx,
		rgName,
		armresources.ResourceGroup{
			Location: to.Ptr(location),
		},
		nil,
	)
	if err != nil {
		return err
	}
	data, err := newResourceGroupsResponse.ResourceGroup.MarshalJSON()

	fmt.Println(string(data))

	// Create virtual Network

	networkClientFactory, err = armnetwork.NewClientFactory(subId, token, nil)
	if err != nil {
		log.Fatal(err)
	}
	virtualNetworksClient = networkClientFactory.NewVirtualNetworksClient()
	subnetsClient = networkClientFactory.NewSubnetsClient()
	securityGroupsClient = networkClientFactory.NewSecurityGroupsClient()
	ipClient = networkClientFactory.NewPublicIPAddressesClient()
	securityGroupsClient = networkClientFactory.NewSecurityGroupsClient()
	nicInterface = networkClientFactory.NewInterfacesClient()

	virtualNetworkResp, err := virtualNetworksClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		vnetName,
		armnetwork.VirtualNetwork{
			Location: to.Ptr(location),
			Properties: &armnetwork.VirtualNetworkPropertiesFormat{
				AddressSpace: &armnetwork.AddressSpace{
					AddressPrefixes: []*string{
						to.Ptr("10.1.0.0/16"),
					},
				},
			},
		},
		nil)

	if err != nil {
		return err
	}
	resp, _ := virtualNetworkResp.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	data, err = resp.VirtualNetwork.MarshalJSON()
	fmt.Println(string(data))

	//create subnet
	subnetPollerResponse, err := subnetsClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		vnetName,
		subnetName,
		armnetwork.Subnet{
			Properties: &armnetwork.SubnetPropertiesFormat{
				AddressPrefix: to.Ptr("10.1.0.0/24"),
			},
		},
		nil,
	)
	if err != nil {
		return err
	}

	subnetResp, _ := subnetPollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	data, err = subnetResp.MarshalJSON()
	fmt.Println(string(data))

	publicIpPollerResp, err := ipClient.BeginCreateOrUpdate(
		ctx,
		rgName,
		publicIpName,
		armnetwork.PublicIPAddress{
			Location: to.Ptr(location),
			Properties: &armnetwork.PublicIPAddressPropertiesFormat{
				PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
			},
		},
		nil,
	)
	if err != nil {
		return err
	}
	publicIpResp, err := publicIpPollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	data, err = publicIpResp.MarshalJSON()
	fmt.Println(string(data))
	//	poller, err := clientFactory.NewResourceGroupsClient().BeginDelete(ctx, "my-resource-group", &armresources.ResourceGroupsClientBeginDeleteOptions{ForceDeletionTypes: to.Ptr("Microsoft.Compute/virtualMachines,Microsoft.Compute/virtualMachineScaleSets")})

	// network security group
	securityGroupPollerResp, err := securityGroupsClient.BeginCreateOrUpdate(ctx, rgName, sgName, armnetwork.SecurityGroup{
		Location: to.Ptr(location),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				{
					Name: to.Ptr("allow-ssh"),
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Description:              to.Ptr("Allow ssh access on port 22"),
						SourceAddressPrefix:      to.Ptr("0.0.0.0/0"),
						DestinationAddressPrefix: to.Ptr("0.0.0.0/0"),
						SourcePortRange:          to.Ptr("*"),
						DestinationPortRange:     to.Ptr("22"),
						Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolTCP),
						Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
						Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound),
						Priority:                 to.Ptr(int32(100)),
					},
				},
			},
			Subnets: []*armnetwork.Subnet{
				{
					Name: subnetResp.Name,
					ID:   subnetResp.ID,
				},
			},
		},
	}, nil,
	)
	if err != nil {
		return fmt.Errorf("could not create or update securtity group rule: %s", err)
	}
	securityGroupResp, err := securityGroupPollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	data, err = securityGroupResp.MarshalJSON()
	fmt.Println(string(data))

	// network interface
	nicPollerResponse, err := nicInterface.BeginCreateOrUpdate(ctx, rgName, networkInterfaceName, armnetwork.Interface{
		Name:     to.Ptr(nicName),
		Location: to.Ptr(location),
		Properties: &armnetwork.InterfacePropertiesFormat{
			Primary: to.Ptr(true),
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID: securityGroupResp.ID,
			},
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("Demo"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						Subnet:          to.Ptr(subnetResp.Subnet),
						PublicIPAddress: to.Ptr(publicIpResp.PublicIPAddress),
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("could not create or update network interface: %s", err)
	}

	nicResp, err := nicPollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	data, err = nicResp.MarshalJSON()
	fmt.Println(string(data))

	// compute
	computeClientFactory, err = armcompute.NewClientFactory(subId, token, nil)
	virtualMachinesClient = computeClientFactory.NewVirtualMachinesClient()
	disksClient = computeClientFactory.NewDisksClient()

	log.Println("start creating virtual machine")

	parameters := armcompute.VirtualMachine{
		Location: to.Ptr(location),
		Identity: &armcompute.VirtualMachineIdentity{
			Type: to.Ptr(armcompute.ResourceIdentityTypeNone),
		},
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					// search image reference
					// az vm image list --output table
					//Offer:     to.Ptr("WindowsServer"),
					//Publisher: to.Ptr("MicrosoftWindowsServer"),
					//SKU:       to.Ptr("2019-Datacenter"),
					//Version:   to.Ptr("latest"),
					//require ssh key for authentication on linux
					Offer:     to.Ptr("UbuntuServer"),
					Publisher: to.Ptr("Canonical"),
					SKU:       to.Ptr("18.04-LTS"),
					Version:   to.Ptr("latest"),
				},
				OSDisk: &armcompute.OSDisk{
					Name:         to.Ptr(diskName),
					CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
					Caching:      to.Ptr(armcompute.CachingTypesReadWrite),
					ManagedDisk: &armcompute.ManagedDiskParameters{
						StorageAccountType: to.Ptr(armcompute.StorageAccountTypesStandardLRS), // OSDisk type Standard/Premium HDD/SSD
					},
					DiskSizeGB: to.Ptr[int32](50), // default 127G
				},
			},
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes("Standard_F2s")), // VM size include vCPUs,RAM,Data Disks,Temp storage.
			},
			OSProfile: &armcompute.OSProfile{ //

				// required for windows-server
				ComputerName:  to.Ptr("admin-compute"),
				AdminUsername: to.Ptr("admin-user"),
				//AdminPassword: to.Ptr("Password01!@#"),
				//require ssh key for authentication on linux
				LinuxConfiguration: &armcompute.LinuxConfiguration{
					DisablePasswordAuthentication: to.Ptr(true),
					SSH: &armcompute.SSHConfiguration{
						PublicKeys: []*armcompute.SSHPublicKey{
							{
								Path:    to.Ptr(fmt.Sprintf("/home/%s/.ssh/authorized_keys", "admin-user")),
								KeyData: to.Ptr(string(pubKey)),
							},
						},
					},
				},
			},
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{
						ID: nicResp.ID,
					},
				},
			},
		},
	}

	pollerResponse, err := virtualMachinesClient.BeginCreateOrUpdate(ctx, rgName, vmName, parameters, nil)
	if err != nil {
		return err
	}

	vmPollerResp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	data, err = vmPollerResp.MarshalJSON()

	fmt.Println(string(data))

	return nil
}

func cleanup(ctx context.Context) {

	log.Println("start deleting virtual machine...")
	err := deleteVirtualMachine(ctx)
	if err != nil {
		log.Fatalf("cannot delete virtual machine:%+v", err)
	}
	log.Println("deleted virtual machine")

	err = deleteDisk(ctx)
	if err != nil {
		log.Fatalf("cannot delete disk:%+v", err)
	}
	log.Println("deleted disk")

	err = deleteNetWorkInterface(ctx)
	if err != nil {
		log.Fatalf("cannot delete network interface:%+v", err)
	}
	log.Println("deleted network interface")

	err = deleteNetworkSecurityGroup(ctx)
	if err != nil {
		log.Fatalf("cannot delete network security group:%+v", err)
	}
	log.Println("deleted network security group")

	err = deletePublicIP(ctx)
	if err != nil {
		log.Fatalf("cannot delete public IP address:%+v", err)
	}
	log.Println("deleted public IP address")

	err = deleteSubnets(ctx)
	if err != nil {
		log.Fatalf("cannot delete subnet:%+v", err)
	}
	log.Println("deleted subnet")

	err = deleteVirtualNetWork(ctx)
	if err != nil {
		log.Fatalf("cannot delete virtual network:%+v", err)
	}
	log.Println("deleted virtual network")

	err = deleteResourceGroup(ctx)
	if err != nil {
		log.Fatalf("cannot delete resource group:%+v", err)
	}
	log.Println("deleted resource group")
	log.Println("success deleted virtual machine.")
}

// delete deleteResourceGroup function
func deleteResourceGroup(ctx context.Context) error {

	pollerResponse, err := clientFactory.NewResourceGroupsClient().BeginDelete(ctx, resourceGroupName, nil)
	if err != nil {
		return err
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

// deleteVirtualNetWork
func deleteVirtualNetWork(ctx context.Context) error {

	pollerResponse, err := virtualNetworksClient.BeginDelete(ctx, resourceGroupName, virtualNetworkName, nil)
	if err != nil {
		return err
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

// deleteSubnet Function
func deleteSubnets(ctx context.Context) error {

	pollerResponse, err := subnetsClient.BeginDelete(ctx, resourceGroupName, virtualNetworkName, subnetName, nil)
	if err != nil {
		return err
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

// deleteNetworkSecurityGroup Function
func deleteNetworkSecurityGroup(ctx context.Context) error {

	pollerResponse, err := securityGroupsClient.BeginDelete(ctx, resourceGroupName, securityGroupName, nil)
	if err != nil {
		return err
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

// deletePublicIP Function
func deletePublicIP(ctx context.Context) error {

	pollerResponse, err := ipClient.BeginDelete(ctx, resourceGroupName, publicIpName, nil)
	if err != nil {
		return err
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

// deleteNetWorkInterface  Function
func deleteNetWorkInterface(ctx context.Context) error {

	pollerResponse, err := nicInterface.BeginDelete(ctx, resourceGroupName, networkInterfaceName, nil)
	if err != nil {
		return err
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

// deleteVirtualMachine Function
func deleteVirtualMachine(ctx context.Context) error {

	pollerResponse, err := virtualMachinesClient.BeginDelete(ctx, resourceGroupName, vmName, nil)
	if err != nil {
		return err
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

// deleteDisk Function
func deleteDisk(ctx context.Context) error {

	pollerResponse, err := disksClient.BeginDelete(ctx, resourceGroupName, diskName, nil)
	if err != nil {
		return err
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}

//func GenerateKeys() ([]byte, []byte, error) {
//	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
//
//	pubKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	return pem.EncodeToMemory(privateKeyPEM), ssh.MarshalAuthorizedKey(pubKey), nil
//}
