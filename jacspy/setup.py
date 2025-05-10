from setuptools import setup, find_packages

setup(
    name="jacs",
    version="0.1.0",
    packages=find_packages(),
    package_data={"jacs": ["jacs.abi3.so", "linux/jacspylinux.so"]},
)
