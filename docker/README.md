# Docker Images

This directory contains the Dockerfiles for the images used in the project.
The goal is to have a simple and easy way to build, run, develop, and test the lightning filter.

There are two images: `base` and `dev`.
The base image contains the necessary dependencies to build the lightning filter,
such as DPDK.
The dev image is based on the base image but also includes tools for development and testing.
The dev image is used to test the lightning filter in the CI pipeline.
