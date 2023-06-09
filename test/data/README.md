# Test data for automated tests

The following subdirectories contain different types of files containing credentials which might be picked up by the various scanning tools

## Why "check"?

Many of the files have the word "check" in their names, indicating that they are test data. We avoid using the word "test" because some tools (such as Trivy) actually ignore such files during their scans. The word "check" is a suitable synonym.