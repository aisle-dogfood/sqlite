/*
** This utility program looks at an SQLite database and determines whether
** or not it is locked, the kind of lock, and who is holding this lock.
**
** This only works on unix when the posix advisory locking method is used
** (which is the default on unix) and when the PENDING_BYTE is in its
** usual place.
*/
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

/* 
 * Validate a file path to prevent path traversal attacks
 * Returns 1 if path is safe, 0 if potentially unsafe
 */
static int isPathSafe(const char *path) {
  char resolved_path[PATH_MAX];
  char *result;
  
  /* Get the absolute path with all symbolic links resolved */
  result = realpath(path, resolved_path);
  if (result == NULL) {
    /* If realpath fails, it could be because the file doesn't exist yet,
       which is a legitimate case for creating new files, or it could be
       due to a path traversal attempt. We'll be conservative and reject it. */
    return 0;
  }
  
  /* At this point, we have a canonicalized path.
     Additional checks could be added here, such as:
     - Ensuring the path is within a specific directory
     - Checking against a whitelist of allowed paths
     - Verifying file extensions
     
     For now, we'll just ensure it's not accessing sensitive system locations */
  if (strncmp(resolved_path, "/etc/", 5) == 0 ||
      strncmp(resolved_path, "/bin/", 5) == 0 ||
      strncmp(resolved_path, "/sbin/", 6) == 0 ||
      strncmp(resolved_path, "/dev/", 5) == 0 ||
      strncmp(resolved_path, "/proc/", 6) == 0 ||
      strncmp(resolved_path, "/sys/", 5) == 0) {
    return 0;
  }
  
  return 1;
}

static void usage(const char *argv0){
  fprintf(stderr, "Usage: %s database\n", argv0);
  exit(1);
}

/* Check for a conflicting lock.  If one is found, print an this
** on standard output using the format string given and return 1.
** If there are no conflicting locks, return 0.
*/
static int isLocked(
  int h,                /* File descriptor to check */
  int type,             /* F_RDLCK or F_WRLCK */
  unsigned int iOfst,   /* First byte of the lock */
  unsigned int iCnt,    /* Number of bytes in the lock range */
  const char *zType     /* Type of lock */
){
  struct flock lk;

  memset(&lk, 0, sizeof(lk));
  lk.l_type = type;
  lk.l_whence = SEEK_SET;
  lk.l_start = iOfst;
  lk.l_len = iCnt;
  if( fcntl(h, F_GETLK, &lk)==(-1) ){
    fprintf(stderr, "fcntl(%d) failed: errno=%d\n", h, errno);
    exit(1);
  }
  if( lk.l_type==F_UNLCK ) return 0;
  printf("%s lock held by %d\n", zType, (int)lk.l_pid);
  return 1;
}

/*
** Location of locking bytes in the database file
*/
#define PENDING_BYTE      (0x40000000)
#define RESERVED_BYTE     (PENDING_BYTE+1)
#define SHARED_FIRST      (PENDING_BYTE+2)
#define SHARED_SIZE       510

/*
** Lock locations for shared-memory locks used by WAL mode.
*/
#define SHM_BASE          120
#define SHM_WRITE         SHM_BASE
#define SHM_CHECKPOINT    (SHM_BASE+1)
#define SHM_RECOVER       (SHM_BASE+2)
#define SHM_READ_FIRST    (SHM_BASE+3)
#define SHM_READ_SIZE     5


int main(int argc, char **argv){
  int hDb;        /* File descriptor for the open database file */
  int hShm;       /* File descriptor for WAL shared-memory file */
  char *zShm;     /* Name of the shared-memory file for WAL mode */
  ssize_t got;    /* Bytes read from header */
  int isWal;                 /* True if in WAL mode */
  int nName;                 /* Length of filename */
  unsigned char aHdr[100];   /* Database header */
  int nLock = 0;             /* Number of locks held */
  int i;                     /* Loop counter */

  if( argc!=2 ) usage(argv[0]);
  
  /* Validate the input path to prevent path traversal attacks */
  if (!isPathSafe(argv[1])) {
    fprintf(stderr, "unsafe path: %s\n", argv[1]);
    exit(1);
  }
  
  hDb = open(argv[1], O_RDONLY, 0);
  if( hDb<0 ){
    fprintf(stderr, "cannot open %s\n", argv[1]);
    return 1;
  }

  /* Make sure we are dealing with an database file */
  got = read(hDb, aHdr, 100);
  if( got!=100 || memcmp(aHdr, "SQLite format 3",16)!=0 ){
    fprintf(stderr, "not an SQLite database: %s\n", argv[1]);
    exit(1);
  }

  /* First check for an exclusive lock */
  if( isLocked(hDb, F_RDLCK, SHARED_FIRST, SHARED_SIZE, "EXCLUSIVE") ){
    return 0;
  }
  isWal = aHdr[18]==2;
  if( isWal==0 ){
    /* Rollback mode */
    if( isLocked(hDb, F_RDLCK, PENDING_BYTE, 1, "PENDING") ) return 0;
    if( isLocked(hDb, F_RDLCK, RESERVED_BYTE, 1, "RESERVED") ) return 0;
    if( isLocked(hDb, F_WRLCK, SHARED_FIRST, SHARED_SIZE, "SHARED") ){
      return 0;
    }
  }else{
    /* WAL mode */
    nName = (int)strlen(argv[1]);
    zShm = malloc( nName + 100 );
    if( zShm==0 ){
      fprintf(stderr, "out of memory\n");
      exit(1);
    }
    memcpy(zShm, argv[1], nName);
    memcpy(&zShm[nName], "-shm", 5);
    
    /* Validate the constructed path as well */
    if (!isPathSafe(zShm)) {
      fprintf(stderr, "unsafe path: %s\n", zShm);
      free(zShm);
      exit(1);
    }
    
    hShm = open(zShm, O_RDONLY, 0);
    if( hShm<0 ){
      fprintf(stderr, "cannot open %s\n", zShm);
      free(zShm);
      return 1;
    }
    if( isLocked(hShm, F_RDLCK, SHM_RECOVER, 1, "WAL-RECOVERY") ){
      free(zShm);
      return 0;
    }
    nLock += isLocked(hShm, F_RDLCK, SHM_CHECKPOINT, 1, "WAL-CHECKPOINT");
    nLock += isLocked(hShm, F_RDLCK, SHM_WRITE, 1, "WAL-WRITE");
    for(i=0; i<SHM_READ_SIZE; i++){
      nLock += isLocked(hShm, F_WRLCK, SHM_READ_FIRST+i, 1, "WAL-READ");
    }
    free(zShm);
  }
  if( nLock==0 ){
    printf("file is not locked\n");
  }
  return 0;
}
