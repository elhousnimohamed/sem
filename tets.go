func init() {
	// Add flags to the remediate command
	remediateCmd.Flags().StringVar(&resourceID, "resource-id", "", "Identifier for the resource to remediate (required)")
	remediateCmd.Flags().StringVar(&targetARN, "target-arn", "", "AWS Resource ARN to remediate (required)")

	// Mark flags as required
	remediateCmd.MarkFlagRequired("resource-id")
	remediateCmd.MarkFlagRequired("target-arn")

	// Add subcommands
	awsCmd.AddCommand(remediateCmd)
	rootCmd.AddCommand(awsCmd)
}
