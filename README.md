# linux-5.11
Our modified codes.

# Configuration

For my GROUP:

1. Do not change `.config` file in this project

2. Run the following codes to prepare the env.

```shell
sudo apt update && sudo apt upgrade
sudo apt-get install git fakeroot build-essential libssl-dev bc flex libelf-dev bison ncurses-devxz-utils
```

3. Choose which module we want to build into linux kernel.

    We just keep it as it is.

    ```shell
    make menuconfig
    ```

4. Then it's time to compile the code, ans install it.

    ```shell
    make -j24
    sudo make modules_install
    sudo make install
    sudo update-grub
    ```

5. Reboot the machine, then choose the right kernel version.


# Problems

1. If you change the `.config` in this repository, you will stuck at compiling the codes.

    For example:
    ```
    *** No rule to make target “debian/canonical-certs.pem”....
    ```

    I delete the certification check to continue the compilation.


2. At the time of system reboot, the following error may be reported
    ```
    vmlinxz-5.11 has invalid signature
    ```

    We need to cancel the signature check.
    ```
    sudo apt install mokutil
    sudo mokutil --disable-validation
    ```
    Then reboot again, choose insecure boot mode.