package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

var (
	region    string
	dryRun    bool
	deleteOld bool
	kmsKeyID  string
)

func init() {
	flag.StringVar(&region, "region", "us-west-2", "AWS region")
	flag.BoolVar(&dryRun, "dry-run", false, "Dry run mode (no changes made)")
	flag.BoolVar(&deleteOld, "delete-old", false, "Delete old resources after encryption")
	flag.StringVar(&kmsKeyID, "kms-key-id", "", "KMS Key ID for encryption (default: AWS managed key)")
}

func main() {
	flag.Parse()
	ctx := context.TODO()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	ec2Client := ec2.NewFromConfig(cfg)

	volumes, err := getUnencryptedUnattachedVolumes(ctx, ec2Client)
	if err != nil {
		log.Fatalf("Failed to retrieve volumes: %v", err)
	}

	if dryRun {
		log.Printf("[DRY RUN] Found %d volumes to encrypt", len(volumes))
		for _, vol := range volumes {
			log.Printf("[DRY RUN] Would encrypt volume: %s (%d GiB) in %s", 
				*vol.VolumeId, *vol.Size, *vol.AvailabilityZone)
		}
		return
	}

	for _, vol := range volumes {
		log.Printf("Processing volume %s", *vol.VolumeId)

		// Create snapshot of original volume
		snap, err := createSnapshot(ctx, ec2Client, vol)
		if err != nil {
			log.Printf("Error creating snapshot: %v", err)
			continue
		}
		log.Printf("Created snapshot %s", *snap.SnapshotId)

		// Create encrypted snapshot
		encryptedSnap, err := copySnapshotEncrypted(ctx, ec2Client, *snap.SnapshotId, kmsKeyID, region)
		if err != nil {
			log.Printf("Error creating encrypted snapshot: %v", err)
			continue
		}
		log.Printf("Created encrypted snapshot %s", *encryptedSnap.SnapshotId)

		// Create new encrypted volume
		newVol, err := createVolumeFromSnapshot(ctx, ec2Client, *encryptedSnap.SnapshotId, vol, kmsKeyID)
		if err != nil {
			log.Printf("Error creating encrypted volume: %v", err)
			continue
		}
		log.Printf("Created encrypted volume %s", *newVol.VolumeId)

		// Cleanup old resources if requested
		if deleteOld {
			if err := deleteResources(ctx, ec2Client, vol, snap, encryptedSnap); err != nil {
				log.Printf("Error cleaning up resources: %v", err)
			}
		}
	}
}

func getUnencryptedUnattachedVolumes(ctx context.Context, client *ec2.Client) ([]types.Volume, error) {
	input := &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{Name: aws.String("encrypted"), Values: []string{"false"}},
			{Name: aws.String("status"), Values: []string{"available"}},
		},
	}

	var volumes []types.Volume
	paginator := ec2.NewDescribeVolumesPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe volumes: %w", err)
		}
		volumes = append(volumes, page.Volumes...)
	}

	return volumes, nil
}

func createSnapshot(ctx context.Context, client *ec2.Client, vol types.Volume) (*types.Snapshot, error) {
	input := &ec2.CreateSnapshotInput{
		VolumeId:    vol.VolumeId,
		Description: aws.String(fmt.Sprintf("Snapshot for encrypting volume %s", *vol.VolumeId)),
		TagSpecifications: []types.TagSpecification{{
			ResourceType: types.ResourceTypeSnapshot,
			Tags:         vol.Tags,
		}},
	}

	result, err := client.CreateSnapshot(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("create snapshot: %w", err)
	}

	if err := waitSnapshotCompleted(ctx, client, *result.SnapshotId); err != nil {
		return nil, err
	}

	return result, nil
}

func copySnapshotEncrypted(ctx context.Context, client *ec2.Client, sourceSnapshotID, kmsKeyID, region string) (*types.Snapshot, error) {
	input := &ec2.CopySnapshotInput{
		SourceRegion:      aws.String(region),
		SourceSnapshotId: aws.String(sourceSnapshotID),
		Encrypted:        aws.Bool(true),
	}

	if kmsKeyID != "" {
		input.KmsKeyId = aws.String(kmsKeyID)
	}

	result, err := client.CopySnapshot(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("copy snapshot: %w", err)
	}

	if err := waitSnapshotCompleted(ctx, client, *result.SnapshotId); err != nil {
		return nil, err
	}

	descOutput, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		SnapshotId: result.SnapshotId,
	})
	if err != nil || len(descOutput.Snapshots) == 0 {
		return nil, fmt.Errorf("describe copied snapshot: %w", err)
	}

	return &descOutput.Snapshots[0], nil
}

func createVolumeFromSnapshot(ctx context.Context, client *ec2.Client, snapshotID string, originalVol types.Volume, kmsKeyID string) (*types.Volume, error) {
	input := &ec2.CreateVolumeInput{
		SnapshotId:       aws.String(snapshotID),
		AvailabilityZone: originalVol.AvailabilityZone,
		VolumeType:       originalVol.VolumeType,
		Size:             originalVol.Size,
		Encrypted:        aws.Bool(true),
		TagSpecifications: []types.TagSpecification{{
			ResourceType: types.ResourceTypeVolume,
			Tags:         originalVol.Tags,
		}},
	}

	if kmsKeyID != "" {
		input.KmsKeyId = aws.String(kmsKeyID)
	}
	if originalVol.Iops != nil {
		input.Iops = originalVol.Iops
	}
	if originalVol.Throughput != nil {
		input.Throughput = originalVol.Throughput
	}

	result, err := client.CreateVolume(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("create volume: %w", err)
	}

	if err := waitVolumeAvailable(ctx, client, *result.VolumeId); err != nil {
		return nil, err
	}

	return result, nil
}

func deleteResources(ctx context.Context, client *ec2.Client, vol types.Volume, snap *types.Snapshot, encryptedSnap *types.Snapshot) error {
	if _, err := client.DeleteVolume(ctx, &ec2.DeleteVolumeInput{
		VolumeId: vol.VolumeId,
	}); err != nil {
		return fmt.Errorf("delete volume: %w", err)
	}
	log.Printf("Deleted old volume %s", *vol.VolumeId)

	if _, err := client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
		SnapshotId: snap.SnapshotId,
	}); err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	log.Printf("Deleted snapshot %s", *snap.SnapshotId)

	if _, err := client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
		SnapshotId: encryptedSnap.SnapshotId,
	}); err != nil {
		return fmt.Errorf("delete encrypted snapshot: %w", err)
	}
	log.Printf("Deleted encrypted snapshot %s", *encryptedSnap.SnapshotId)

	return nil
}

func waitSnapshotCompleted(ctx context.Context, client *ec2.Client, snapshotID string) error {
	waiter := ec2.NewSnapshotCompletedWaiter(client)
	return waiter.Wait(ctx, &ec2.DescribeSnapshotsInput{
		SnapshotId: aws.String(snapshotID),
	}, 30*time.Minute)
}

func waitVolumeAvailable(ctx context.Context, client *ec2.Client, volumeID string) error {
	waiter := ec2.NewVolumeAvailableWaiter(client)
	return waiter.Wait(ctx, &ec2.DescribeVolumesInput{
		VolumeIds: []string{volumeID},
	}, 5*time.Minute)
}
