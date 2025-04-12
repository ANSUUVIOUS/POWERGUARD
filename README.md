# Power Guard

The primary purpose of this project was to provide an AV plugin that created a new technique of AV Detection, by gathering metrics
based on GPU usage at the process level and **OVERALL** consumption. The way this was possible to do was by using the NVIDIA Management Library (**NVML**) along with the (Windows Management Instrumentation) **WMI**. 

This also consists of having the following metriics for AV detection:

- CPU Usage
- Battery Usage (Laptops)
- Power wattage estimated use

This plugin consists of using the following to perform it's operation:

- An application level process that monitors the metrics described above, kills processes, and runs the ML model for detection
- An ML model that verifies if the opcodes of a process are malicious or not
- A Kernel level driver that gathers system process info, processes that are running on the system, and a forced termination techbique that **guarantees** succssful killing of the process

## Execution Instructions

Once complied in Visual Studio, you just need to run the following:

```
.\Power_exp.exe
```

This will allow for the plugin to be able to run - prior to compilation, you need to install the [PowerGuard Driver](https://github.com/ANSUUVIOUS/CryptoStomper_AV_Driver/tree/master), and the ML model that is needed for the successful operation of the software.
