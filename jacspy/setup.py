from setuptools import setup, find_packages

setup(
    name="jacspy",
    version="0.1.0",
    packages=find_packages(),
    package_data={"jacspy": ["jacspy.so", "linux/jacspylinux.so"]},
)
