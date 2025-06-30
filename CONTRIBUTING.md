# Contributing to SBOM Auditor Action

First off, thank you for considering contributing to this project! We welcome any kind of contribution, from reporting bugs and suggesting enhancements to submitting code changes.

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please open an issue on GitHub. Make sure to include:
- A clear and descriptive title.
- A detailed description of the problem.
- Steps to reproduce the bug.
- The expected behavior and what actually happened.
- Your environment (e.g., operating system, runner version).

### Suggesting Enhancements

If you have an idea for a new feature or an improvement to an existing one, please open an issue on GitHub. Describe your idea clearly and explain why it would be valuable to the project.

### Your First Code Contribution

Unsure where to begin? You can start by looking for issues tagged with `good first issue`.

## Development Setup

To get started with development, you'll need Python 3.9 or newer.

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```sh
    git clone https://github.com/YOUR_USERNAME/sbom_auditor_action.git
    cd sbom_auditor_action
    ```
3.  **Set up a virtual environment** (recommended):
    ```sh
    python3 -m venv .venv
    source .venv/bin/activate
    ```
4.  **Install the dependencies**: The action's dependencies are listed in `action.yml`. You can install them using pip:
    ```sh
    pip install requests tqdm openai
    ```

## Running Tests

We use Python's built-in `unittest` framework for testing. To run the tests, execute the following command from the root of the repository:

```sh
python3 -m unittest discover helpers
```

Please make sure all tests pass before submitting a pull request.

## Submitting Changes

1.  Create a new branch for your changes:
    ```sh
    git checkout -b feature/your-amazing-feature
    ```
2.  Make your changes and add or update tests as needed.
3.  Commit your changes with a clear and descriptive commit message.
4.  Push your branch to your fork on GitHub:
    ```sh
    git push origin feature/your-amazing-feature
    ```
5.  Open a **Pull Request** from your fork to the `main` branch of the original repository.
6.  In the pull request description, clearly explain the changes you've made and link to any relevant issues.

We will review your pull request as soon as possible. Thank you for your contribution!
