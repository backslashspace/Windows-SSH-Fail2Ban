using System.ServiceProcess;

namespace F2B_SRV
{
    internal static class SRV_Init
    {
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new SRV_Info()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}