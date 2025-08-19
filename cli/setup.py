from setuptools import setup, find_packages

setup(
    name="dvs",
    version="0.2",
    packages=find_packages(),
    install_requires=["setuptools", "termcolor"],
    entry_points={
        "console_scripts": [
            "dvs=dvs.__main__:main",
        ],
    },
)