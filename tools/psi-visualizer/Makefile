
check-requirements:
	@command -v python3 >/dev/null 2>&1 || { echo >&2 "Python3 is required but it's not installed.  Aborting."; exit 1; }
	@command -v pip >/dev/null 2>&1 || { echo >&2 "Pip is required but it's not installed.  Aborting."; exit 1; }

prepare-env: check-requirements
	@if [ ! -d "venv" ]; then \
		python3 -m venv venv; \
		. venv/bin/activate; \
		pip install -r requirements.txt; \
	fi

# Print help message, how to use activate the environment
activate-env: prepare-env
	@echo -e "To activate the environment, run:\n\tsource venv/bin/activate"
	@echo -e "To run the visualizer, run:\n\tpython3 visualize.py <path-to-psi-file>"
	@echo -e "To deactivate the environment later, run:\n\tdeactivate"

