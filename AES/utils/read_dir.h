/**
 * read all file names from a directory
**/
#define MAX_FILE_NUM 1000
#define CHAR_BUFFER 1000

struct file_list{
  char *files[MAX_FILE_NUM];
  int file_num;
};

struct file_list read_dir(char *base_path);

char *get_file_text(char *path);
