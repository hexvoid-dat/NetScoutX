# Contributing to NetScoutX

We welcome and appreciate contributions to NetScoutX! By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

There are many ways to contribute, from reporting bugs to suggesting new features, writing documentation, or submitting code changes.

### 1. Reporting Bugs

If you find a bug, please open an issue on our GitHub repository. Before opening a new issue, please:

*   **Search existing issues:** Your bug might have already been reported.
*   **Provide detailed information:**
    *   A clear and concise description of the bug.
    *   Steps to reproduce the behavior.
    *   Expected behavior vs. actual behavior.
    *   Your operating system and Go version.
    *   Any relevant logs or error messages.

### 2. Suggesting Enhancements

We're always looking for ways to improve NetScoutX. If you have an idea for a new feature or an enhancement to an existing one, please open an issue. Describe your suggestion clearly, explaining its benefits and potential use cases.

### 3. Code Contributions

If you'd like to contribute code, please follow these steps:

#### a. Setup Your Development Environment

1.  **Fork the repository:** Click the "Fork" button on GitHub.
2.  **Clone your fork:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/net-scout.git
    cd net-scout
    ```
3.  **Install dependencies:**
    ```bash
    go mod tidy
    ```
4.  **Install `libpcap` development libraries:** (See [INSTALL.md](INSTALL.md) for details)
    *   Ubuntu/Debian: `sudo apt-get install libpcap-dev`
    *   macOS: `brew install libpcap`

#### b. Branching Model

We use a `main` branch for stable releases and feature branches for development.

1.  **Create a new branch:**
    ```bash
    git checkout -b feature/your-feature-name main
    # or
    git checkout -b bugfix/your-bug-fix main
    ```
    Choose a descriptive name for your branch.

#### c. Code Style

*   Follow standard Go idioms and best practices.
*   Use `gofmt` to format your code: `go fmt ./...`
*   Ensure your code passes `golint` and `go vet`: `golint ./...` and `go vet ./...`
*   Add comments where necessary to explain complex logic.

#### d. Running Tests

Before submitting a Pull Request, ensure all tests pass:

```bash
go test ./...
```

If you add new functionality, please write corresponding unit tests. For passive parsers, this involves creating `.pcap` files in `internal/passive/testdata/` and writing tests that process them.

#### e. Commit Style

We prefer clear, concise commit messages. A good commit message typically has:

*   A short, descriptive subject line (max 50-72 chars).
*   An optional, more detailed body explaining *what* the change is, *why* it was made, and *how* it addresses the problem or implements the feature.

Example:
```
feat: Add passive DHCP server detection

This commit introduces passive DHCP server detection.
It parses DHCP OFFER/ACK packets to identify server IPs and MACs.
Adds a heuristic to flag potential rogue DHCP servers based on vendor OUI
and multiple servers on the segment.
```

#### f. Submitting a Pull Request (PR)

1.  **Push your branch to your fork:**
    ```bash
    git push origin feature/your-feature-name
    ```
2.  **Open a Pull Request:** Go to the NetScoutX GitHub repository and open a new PR from your forked branch to the `main` branch.
3.  **Provide a clear description:**
    *   Reference any related issues (e.g., `Fixes #123`, `Closes #456`).
    *   Explain the changes you've made.
    *   Describe how you've tested your changes.
    *   Include any relevant screenshots or output if it's a UI change.

### 4. Adding New Protocol Parsers (for Passive Engine)

If you're adding a new protocol parser to the `internal/passive` engine:

1.  **Create `parser_yourprotocol.go`:** Implement the parsing logic in a new file.
2.  **Update `engine.go`:** Add a dispatch rule in `dispatchPacket` to send relevant packets to your new parser.
3.  **Update `model.go`:** Add any new fields to `passive.Host` or `AnalysisResult` needed for your parser.
4.  **Update `heuristics.go`:** Add any new heuristics for anomaly detection related to your protocol.
5.  **Write Tests:** Create a `.pcap` file in `internal/passive/testdata/` with sample traffic for your protocol and write a corresponding test in `internal/passive/passive_test.go`.

## Code of Conduct

Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

---
