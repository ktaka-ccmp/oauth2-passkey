# Contributing to oauth2-passkey

Thank you for your interest in contributing to oauth2-passkey! We welcome contributions from the community.

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub with:

- Clear description of the problem or feature
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Relevant environment details

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** for your changes: `git checkout -b feature/your-feature-name`
3. **Make your changes** following the project's coding style
4. **Test your changes** by running the test suite: `cargo test`
5. **Commit your changes** with clear, descriptive commit messages
6. **Push** to your fork: `git push origin feature/your-feature-name`
7. **Open a Pull Request** with a clear description of your changes

### Development Setup

1. Clone the repository
2. Install Rust (latest stable version recommended)
3. Set up the development environment:

   ```bash
   # Install dependencies
   cargo build

   # Run tests
   cargo test

   # Run individual crate tests
   cd oauth2_passkey && cargo test
   cd oauth2_passkey_axum && cargo test
   ```

### Code Guidelines

- Follow Rust naming conventions and idioms
- Write tests for new functionality
- Update documentation as needed
- Ensure your code compiles without warnings
- Keep dependencies minimal (library design principle)

### Testing

- Run the full test suite before submitting: `cargo test`
- Add tests for new features or bug fixes
- Ensure all existing tests pass

## License

By contributing to this project, you agree that your contributions will be licensed under the same terms as the project (MIT OR Apache-2.0 dual license).

## Questions?

Feel free to open an issue for questions about contributing or reach out to the maintainers.
