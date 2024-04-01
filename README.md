# Cobalt Strike Beacon

## Overview

This is a project I have saved on my computer, I just didn't think I should keep it private since I can no longer find it anywhere on the internet. This project aims to provide a fully functional, from-scratch alternative to the Cobalt Strike Beacon, providing transparency and flexibility to security professionals and enthusiasts.

This project is not a reverse-engineered version of the Cobalt Strike Beacon, but a complete open source implementation. The "settings.h" file contains macros for the C2 configuration file and the user should complete it to their liking. Once you have your "settings.h" template ready, feel free to share and contribute.

PS. explain something.I don’t remember who deleted it after it was made public, but I read this project and I think it can help many people who are trying to reconstruct Beacon.

## Prerequisites

- Visual Studio: The project is built using Visual Studio, not Visual Studio Code.
- [libtommath](https://github.com/libtom/libtommath): A fast, portable number-theoretic multiple-precision integer library.
- [libtomcrypt](https://github.com/libtom/libtomcrypt): A modular and portable cryptographic toolkit.

## Getting Started

1. Clone the repository

2. Open the project in Visual Studio.

3. Ensure that the required dependencies (libtommath, libtomcrypt) are properly configured and linked with the project.

4. Build the project.

5. Create your `settings.h` file based on the provided template. Make sure to include your C2 Profile macros and configurations.

6. Build the project again to apply your custom settings.

7. Execute the compiled binary.
