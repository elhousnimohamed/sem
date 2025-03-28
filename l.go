// List server certificates
	input := &iam.ListServerCertificatesInput{
		// Optional: you can add MaxItems or Marker for pagination if needed
	}

	// Call ListServerCertificates
	resp, err := svc.ListServerCertificates(input)
	if err != nil {
		log.Fatalf("Failed to list server certificates: %v", err)
	}

	// Iterate through certificates to check for existence
	for _, cert := range resp.ServerCertificateMetadataList {
		if *cert.ServerCertificateName == certificateName {
			return true
		}
	}
