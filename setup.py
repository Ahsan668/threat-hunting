from setuptools import setup, find_packages

setup(
    name="threat-hunter",
    version="0.1.0",
    author="Ahsan Raza",
    description="Automated threat intelligence and IOC hunting platform",
    packages=find_packages(),
    install_requires=[
        "click>=8.1",
        "requests>=2.31",
        "python-dotenv>=1.0",
        "pyyaml==6.0.3",
        "pydantic>=2.0",
        "flask>=3.0",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "threat-hunter=threat_hunter.__main__:main",
        ],
    },
)
