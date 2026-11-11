using System;
using System.IO;
using LLama.Common;
using LLama;

using AutoCommand.Agent.Core;
using AutoCommand.Contain.Core;
using AutoCommand.Forensics.Core;
using AutoCommand.NetWatch.Core;
using AutoCommand.Sitedoctor.Core;

namespace ScratchTest
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string prefsPath = @"C:\Users\honey\AutoCommand\bin\Debug\net10.0-windows\gemini_model_prefs.txt";
                if (!File.Exists(prefsPath))
                {
                    Console.WriteLine("Prefs file not found.");
                    return;
                }

                var lines = File.ReadAllLines(prefsPath);
                if (lines.Length < 2)
                {
                    Console.WriteLine("Prefs file missing model info.");
                    return;
                }

                string modelPath = lines[1].Trim();
                Console.WriteLine($"Trying to load: {modelPath}");

                if (!File.Exists(modelPath))
                {
                    Console.WriteLine("Model file does not exist on disk.");
                    return;
                }

                var parameters = new ModelParams(modelPath)
                {
                    ContextSize = 4096,
                    GpuLayerCount = 99
                };

                Console.WriteLine("Calling LLamaWeights.LoadFromFile...");
                var model = LLamaWeights.LoadFromFile(parameters);
                Console.WriteLine("Model weights loaded successfully.");
                
                var context = model.CreateContext(parameters);
                Console.WriteLine("Model context created successfully.");
                
                context.Dispose();
                model.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION CAUGHT:");
                Console.WriteLine(ex.ToString());
            }
        }
    }
}
