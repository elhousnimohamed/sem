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


Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := config.LoadConfig()
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}

		// Extract account ID from target ARN
		parts := strings.Split(targetARN, ":")
		if len(parts) < 5 {
			log.Fatalf("Invalid target ARN format: %s", targetARN)
		}
		accountID := parts[4]

		// Assume AWS role
		awsCfg, err := auth.AssumeAWSRole(accountID, cfg.EntityName)
		if err != nil {
			log.Fatalf("Failed to assume AWS role: %v", err)
		}

		// Handle remediation
		ctx := cmd.Context()
		if err := remediation.HandleRemediation(ctx, awsCfg, resourceID, targetARN); err != nil {
			log.Fatalf("Remediation failed: %v", err)
		}

		fmt.Printf("Successfully remediated resource %s\n", resourceID)
	},
