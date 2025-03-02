# CLAUDE.md - GenOpti-OS Coding Guidelines

## Build/Run Commands
- Setup environment: `python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt`
- Run app locally: `python app.py`
- Run with debug mode: `DEBUG_MODE=1 python app.py`
- Install as service: `sudo ./install_genopti-os.sh`
- Setup UI kiosk mode: `./ui_setup.sh`
- View logs: `tail -f logs/scanner.log`

## Code Style Guidelines
- **Imports**: Group in order: stdlib, third-party, local imports
- **Naming**: Use snake_case for variables/functions, UPPER_CASE for constants, PascalCase for classes
- **Error Handling**: Always wrap external operations in try/except blocks with specific logging
- **Documentation**: Add docstrings for all functions and classes using triple quotes
- **Formatting**: Use 4-space indentation, no tabs
- **Logging**: Use the logging module with proper levels (INFO, DEBUG, ERROR) not print()
- **Comments**: Use section headers with dashed lines as shown in app.py
- **JavaScript**: Use camelCase for variables/functions, clear comments for complex logic

This project is a Flask-based application for license scanning and validation with a kiosk web interface, designed for Raspberry Pi hardware.