from setuptools import setup, find_packages

setup(
    name="forensectl",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.0",
        "typer>=0.9.0",
        "pydantic>=2.5.0",
        "jinja2>=3.1.2",
        "pyyaml>=6.0.1",
        "requests>=2.31.0",
        "psutil>=5.9.6",
        "pandas>=2.1.4",
        "numpy>=1.26.2",
        "cryptography>=41.0.7",
        "sqlalchemy>=2.0.23",
    ],
    entry_points={
        "console_scripts": [
            "forensectl=forensectl.cli:main",
        ],
    },
    python_requires=">=3.8",
)