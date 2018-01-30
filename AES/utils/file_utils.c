#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>

#include "file_utils.h"

struct file_list read_dir(char *base_path){
  DIR *dir;
  struct dirent *ptr;
  struct file_list fl;
  for(int i = 0; i < MAX_FILE_NUM; i++){
    fl.files[i] = "";
  }
  fl.file_num = 0;
  int j = 0;

  if((dir = opendir(base_path)) == NULL){
    fprintf(stderr, "open dir %s error...\n", base_path);
    exit(1);
  }

  while ((ptr = readdir(dir)) != NULL ){
    if(strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0){ //current dir or parent dir
      continue;
    }else if(ptr->d_type == 8){ //file
      fl.files[fl.file_num++] = ptr->d_name;
    }else if(ptr->d_type == 10){  //link file
      continue;
    }else if(ptr->d_type == 4){ //dir
      continue;
    }
  }
  closedir(dir);
  return fl;
}

char *get_file_text(char *path){
  FILE *fp;
  char *text;

  fp = fopen(path, "r");
  if (fp == NULL){
    printf("cannot open file %s\n", path);
    return NULL;
  }
  fseek(fp, 0, SEEK_END);
  int len = ftell(fp);
  text = (char *)malloc((len + 1) * sizeof(char));
  rewind(fp);
  // char str[(CHAR_BUFFER + 1)];
  // while(fgets(str, CHAR_BUFFER, fp) != NULL){
  //   strcat(text, str);
  // }
  len = fread(text, 1, len, fp);
  text[len] = '\0';
  fclose(fp);
  return text;
}

void write_result(char *res_file, int p_len, int c_len, double enc_time, double dec_time, double renc_time){
  FILE *out = fopen(res_file, "a");
  if (out == NULL){
    printf("cannot open file %s\n", res_file);
    return;
  }
  fprintf(out, "%d,%d,%lf,%lf,%lf\n", p_len, c_len, enc_time, dec_time, renc_time);
  fclose(out);
  return;
}
