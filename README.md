# PwnBrute

A small wrapper for probabilistic exploits based on [pwntools](https://github.com/Gallopsled/pwntools)


### Problem

Often in CTF competitions, the player is offered tasks that are solved by unstable exploits which
depend on external factors (such as the value of ASLR, the presence of race conditions, etc.). Therefore,
you have to run them **a lot of times**. However, this task can be handed to pwnbrute, which will do it
quite simply and quickly


### Usage

1. Move the exploit logic in a separate function and pass it to the `brute` function
2. In your exploit, after passing the probabilistic part, add a call to the `success` function,
    which will return console to the exploit
3. Run the exploit as usual and get a profit!!!

For detailed usage see the [examples](examples/)
