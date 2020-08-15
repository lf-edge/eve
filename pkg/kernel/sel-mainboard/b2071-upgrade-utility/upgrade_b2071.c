//////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2014 Schweitzer Engineering Laboratories, Inc.
// SEL Confidential
///
/// @brief Utility to push an upgrade file to the mainboard
//////////////////////////////////////////////////////////////////////////////

#include <errno.h>   // err codes
#include <fcntl.h>   // open
#include <stdint.h>  // std types
#include <stdio.h>   // I/O
#include <stdlib.h>  // std functions
#include <string.h>  // string functions
#include <sys/types.h>
#include <unistd.h>  // getuid

//////////////////////////////////////////////////////////////////////////////
/// @brief Entry function to the application
///
/// @param[in] argc Number of command line arguments
/// @param[in] argv Command line arguments that should contain the file to be
///                 pushed to the mainboard.
///
/// @return EXIT_SUCCESS if the file was successfully pushed, EXIT_FAILURE
///         otherwise.
//////////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
   int driver;
   int file;
   size_t len;
   int err = EXIT_SUCCESS;

   // Check for Administrative privledges
   if(geteuid() != 0)
   {
      fprintf(stderr,
         "Insufficient privileges, please run as administrator.\n");
      return EXIT_FAILURE;
   }
   
   // Make sure an argument was passed in.
   if(argc != 2)
   {
      fprintf(stderr, "Upgrade package was not specified.\n");
      return EXIT_FAILURE;
   }

   // Verify the file extension
   len = strlen(argv[1]);
   if(strcmp(&(argv[1][len-4]), ".dat") != 0)
   {
      fprintf(stderr, "Incorrect extension for upgrade file.\n");
      return EXIT_FAILURE;
   }

   // Attempt to open the upgrade file
   file = open(argv[1], O_RDWR);
   if(file < 0)
   {
      fprintf(stderr, "File %s does not exist.\n", argv[1]);
      return EXIT_FAILURE;
   }

   // Attempt to open the driver
#if defined(__VMKLNX__)
   driver = open("/vmfs/devices/selb2071upg", O_RDWR);
#else // defined(__LINUX__)
   driver = open("/dev/selb2071upg", O_RDWR);
#endif
   if(driver < 0)
   {
      fprintf(stderr, 
         "Mainboard upgrade driver is not installed or is unavailable.\n");
      close(file);
      return EXIT_FAILURE;
   }

   // Read the upgrade file and dump it to the driver
   while(err == EXIT_SUCCESS)
   {
      uint8_t buffer[4096];
      ssize_t bytes_read = 0;
      ssize_t bytes_written = 0;

      bytes_read = read(file, buffer, sizeof(buffer));

      if (bytes_read < 0)
      {
         fprintf(stderr, "Can not read from upgrade data file.\n");
         err = EXIT_FAILURE;
         break;
      }

      fprintf(stdout, ".");
      fflush(stdout);

      if (bytes_read == 0)
      {
         break;
      }

      bytes_written = write(driver, buffer, bytes_read);

      if (bytes_written <= 0)
      {
         fprintf(stderr, "Can not write data to the upgrade driver.\n");
         err = EXIT_FAILURE;
         break;
      }

      fprintf(stdout, ".");
      fflush(stdout);

      if (bytes_written != bytes_read)
      {
         printf("Error writing upgrade data file to the device.\n");
         err = EXIT_FAILURE;
         break;
      }
   }

   // Check for success
   uint8_t timeout = 0;
   while(err == EXIT_SUCCESS) {
      uint8_t buffer[1];
      ssize_t bytes_read = 0;

      bytes_read = read(driver, buffer, 1);

      if(bytes_read == 0)
      {
         fprintf(stdout, "\nSuccess.  Please restart computer to apply update.\n");
         break;
      } 
      
      else if(errno != EBUSY)
      {
         fprintf(stderr, "\nFailure.\n");
         err = EXIT_FAILURE;
         break;
      }

      else if(timeout == 5)
      {
         fprintf(stderr, "\nTimeout Failure.\n");
      }

      sleep(1);
      timeout++;
   }

   close(driver);
   close(file);

   return err;
}


