
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
int main(){
  int BUFFER_LENGTH =256; 
  FILE* filePointer;
  char buffer[BUFFER_LENGTH];
  char save[100][BUFFER_LENGTH];
  filePointer = fopen("config.txt", "r");

  int i = 0;
  int j=0;
  int ret, fd;

   while(fgets(save[i], BUFFER_LENGTH, filePointer)) {
      printf("%s", save[i]);
	   i++;
   }
   fclose(filePointer);
   printf("\nStarting device test code example...\n");
   fd = open("/dev/firewall", O_RDWR);             // Open the device with read/write access
   //printf("open\n");
   if (fd < 0){
      perror("Failed to open the device...");
      return errno;
   }
   for(j=0; j < i; j++){
     ret = write(fd, save[j], BUFFER_LENGTH); // Send the string to the LKM
     if (ret < 0){
        perror("Failed to write the message to the device.");
        return errno;
     }
   }
   printf("End of the program\n");
   return 0;
}
