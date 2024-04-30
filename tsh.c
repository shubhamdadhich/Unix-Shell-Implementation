/* $begin tshref-ans */
/* 
 * tsh - A tiny shell program with job control
 * 
 * <Put your name and login ID here>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

/* Misc manifest constants */
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a command line */
#define MAXJOBS      16   /* max jobs at any point in time */
#define MAXJID    1<<16   /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

/* 
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;      /* defined in libc */
char prompt[] = "tsh> ";    /* command line prompt (DO NOT CHANGE) */
int verbose = 0;            /* if true, print additional output */
int nextjid = 1;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */

struct job_t {              /* The job struct */
  pid_t pid;              /* job PID */
  int jid;                /* job ID [1, 2, ...] */
  int state;              /* UNDEF, BG, FG, or ST */
  char cmdline[MAXLINE];  /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */
/* End global variables */


/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bg(int jid);
void do_fg(int jid);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv, int cmdnum); 
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs); 
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid); 
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid); 
int pid2jid(pid_t pid); 
void listjobs(struct job_t *jobs);

void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);

ssize_t sio_puts(char s[]);
ssize_t sio_putl(long v);
static size_t sio_strlen(char s[]);
static void sio_ltoa(long v, char s[], int b);
static void sio_reverse(char s[]);


/*
 * main - The shell's main routine 
 */
int main(int argc, char **argv) 
{
  char c;
  char cmdline[MAXLINE];
  int emit_prompt = 1; /* emit prompt (default) */

  /* Redirect stderr to stdout (so that driver will get all output
   * on the pipe connected to stdout) */
  dup2(1, 2);

  /* Parse the command line */
  while ((c = getopt(argc, argv, "hvp")) != EOF) {
    switch (c) {
    case 'h':             /* print help message */
      usage();
      break;
    case 'v':             /* emit additional diagnostic info */
      verbose = 1;
      break;
    case 'p':             /* don't print a prompt */
      emit_prompt = 0;  /* handy for automatic testing */
      break;
    default:
      usage();
    }
  }

  /* Install the signal handlers */

  /* These are the ones you will need to implement */
  Signal(SIGINT,  sigint_handler);   /* ctrl-c */
  Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
  Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

  /* This one provides a clean way to kill the shell */
  Signal(SIGQUIT, sigquit_handler); 

  /* Initialize the job list */
  initjobs(jobs);

  /* Execute the shell's read/eval loop */
  while (1) {

    /* Read command line */
    if (emit_prompt) {
      printf("%s", prompt);
      fflush(stdout);
    }
    if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
      app_error("fgets error");
    if (feof(stdin)) { /* End of file (ctrl-d) */
      fflush(stdout);
      exit(0);
    }

    /* Evaluate the command line */
    eval(cmdline);
    fflush(stdout);
    fflush(stdout);
  } 

  exit(0); /* control never reaches here */
}
  
/* 
 * eval - Evaluate the command line that the user has just typed in
 * 
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.  
 */
void eval(char *cmdline) 
{
  /* $begin handout */
  char *argv1[MAXARGS]; /* argv for execve() */
  char *argv2[MAXARGS]; /* argv for execve() */
  int bg;               /* should the job run in bg or fg? */
  pid_t pid1;           /* process id */
  pid_t pid2 = -1;      /* process id for second command if piping */
  sigset_t mask;        /* signal mask */

  /* If the line contains two commands, split into two strings */
  char* cmd2 = strchr(cmdline, '|');
  
  if(cmd2 != NULL && strlen(cmd2) >= 3 && (cmd2 - cmdline) >= 2){
    // Terminate the first command with newline and null character
    cmd2--;
    cmd2[0] = '\n';
    cmd2[1] = '\0';
    // Set the second command to start after the next space
    cmd2 += 3;
  }

  /* Parse command line */
  bg = parseline(cmdline, argv1, 1); 
  if (argv1[0] == NULL)  
    return;   /* ignore empty lines */

  if(cmd2 != NULL)
    parseline(cmd2, argv2, 2);

  // TODO: Execute the command(s)
  //       If cmd2 is NULL, then there is only one command


  if (!builtin_cmd(argv1)) { 
    
    /* 
     * This is a little tricky. Block SIGCHLD, SIGINT, and SIGTSTP
     * signals until we can add the job to the job list. This
     * eliminates some nasty races between adding a job to the job
     * list and the arrival of SIGCHLD, SIGINT, and SIGTSTP signals.  
     */
    
    if (sigemptyset(&mask) < 0)
      unix_error("sigemptyset error");
    if (sigaddset(&mask, SIGCHLD)) 
      unix_error("sigaddset error");
    if (sigaddset(&mask, SIGINT)) 
      unix_error("sigaddset error");
    if (sigaddset(&mask, SIGTSTP)) 
      unix_error("sigaddset error");
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
      unix_error("sigprocmask error");
  

    int fd[2];
    if(cmd2 != NULL)
    {
      pipe(fd);
    }
    
    /* Create a child process */
    if ((pid1 = fork()) < 0)
      unix_error("fork error");
    
    /* 
     * Child  process(es) 
     */
    if (pid1 == 0) {

      /* Setup pipe to second command */
      if(cmd2 != NULL)
      {
	dup2(fd[1], 1);
	close(fd[0]);
      }

      /* Child unblocks signals */
      sigprocmask(SIG_UNBLOCK, &mask, NULL);
      
      /* Each new job must get a new process group ID 
	 so that the kernel doesn't send ctrl-c and ctrl-z
	 signals to all of the shell's jobs */
      if (setpgid(0, 0) < 0) 
	unix_error("setpgid error"); 
      
      /* Now load and run the program in the new job */
      if (execve(argv1[0], argv1, environ) < 0) {
	printf("%s: Command not found\n", argv1[0]);
	exit(0);
      }
    }
    
    /* Child 2 */
    if(cmd2 != NULL)
    {
      /* Create a child process */
      if ((pid2 = fork()) < 0)
	unix_error("fork error");
      

      if (pid2 == 0) {
	
	/* Setup pipe from first command */
	dup2(fd[0], 0);
	close(fd[1]);
	
	/* Child unblocks signals */
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
	
	/* Each new job must get a new process group ID 
	   so that the kernel doesn't send ctrl-c and ctrl-z
	   signals to all of the shell's jobs */
	if (setpgid(0, 0) < 0) 
	  unix_error("setpgid error"); 
	
	/* Now load and run the program in the new job */
	if (execve(argv2[0], argv2, environ) < 0) {
	  printf("%s: Command not found\n", argv2[0]);
	  exit(0);
	}
      }
    }

    /* 
     * Parent process
     */
    
    // Close extra FDs
    if(cmd2) {
      close(fd[0]);
      close(fd[1]);
    }

    /* Parent adds the job, and then unblocks signals so that
       the signals handlers can run again */
    addjob(jobs, pid1, (bg == 1 ? BG : FG), cmdline);

    if(cmd2 != NULL)
      addjob(jobs, pid2, FG, cmd2); // pipe commands are always in FG

    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    
    if (!bg) 
    {
      waitfg(pid1);
      if(cmd2 != NULL)
	waitfg(pid2);
    }
    else
      printf("[%d] (%d) %s", pid2jid(pid1), pid1, cmdline); // BG job can not have a second command
  }
  /* $end handout */
  return;
}

/* 
 * parseline - Parse the command line and build the argv array.
 * 
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.  
 */
int parseline(const char *cmdline, char **argv, int cmdnum) 
{
  static char array1[MAXLINE]; /* holds local copy of command line */
  static char array2[MAXLINE]; /* holds local copy of 2nd command line */
  char *buf;                   /* ptr that traverses command line */
  char *delim;                 /* points to first space delimiter */
  int argc;                    /* number of args */
  int bg;                      /* background job? */
  
  if(cmdnum == 1)
    buf = array1;
  else
    buf = array2;
  
  strcpy(buf, cmdline);
  
  buf[strlen(buf)-1] = ' ';  /* replace trailing '\n' with space */
  while (*buf && (*buf == ' ')) /* ignore leading spaces */
    buf++;
  
  /* Build the argv list */
  argc = 0;
  if (*buf == '\'') {
    buf++;
    delim = strchr(buf, '\'');
  }
  else {
    delim = strchr(buf, ' ');
  }
  
  while (delim) {
    argv[argc++] = buf;
    *delim = '\0';
    buf = delim + 1;
    while (*buf && (*buf == ' ')) /* ignore spaces */
      buf++;
    
    if (*buf == '\'') {
      buf++;
      delim = strchr(buf, '\'');
    }
    else {
      delim = strchr(buf, ' ');
    }
  }
  argv[argc] = NULL;
  
  if (argc == 0)  /* ignore blank line */
    return 1;
  
  /* should the job run in the background? */
  if ((bg = (*argv[argc-1] == '&')) != 0) {
    argv[--argc] = NULL;
  }
  
  
  return bg;
}

/* 
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.  
 */
int builtin_cmd(char **argv) 
{
  /* $begin handout */
  char *cmd = argv[0];

  if (!strcmp(cmd, "quit")) { /* quit command */
    exit(0);  
  }

  if (!strcmp(cmd, "jobs")) { /* jobs command */
    listjobs(jobs);
    return 1;    
  }

  if (!strcmp(cmd, "bg") || !strcmp(cmd, "fg")) { /* bg and fg commands */
      
    int jid;

    /* Ignore command if no argument */
    if (argv[1] == NULL) {
      printf("%s command requires a %%jobid argument\n", argv[0]);
      return 1;
    }

    if (argv[1][0] == '%') {
      jid = atoi(&argv[1][1]);
    }
    else {
      printf("%s: argument must be a %%jobid\n", argv[0]);
      return 1;
    }
      
    if(!strcmp(cmd, "bg"))
      do_bg(jid);
    else
      do_fg(jid);
    return 1;
  }

  if (!strcmp(cmd, "&")) { /* Ignore singleton & */
    return 1;
  }
  /* $end handout */
  return 0;     /* not a builtin command */
}

/* 
 * do_bg - Execute the builtin bg command
 */
void do_bg(int jid) 
{
  /* $begin handout */
  struct job_t *jobp=NULL;
  
  if (!(jobp = getjobjid(jobs, jid))) {
    printf("%%%d: No such job\n", jid);
    return;
  }
  
  if (kill(-(jobp->pid), SIGCONT) < 0)
    unix_error("kill (bg) error");
  jobp->state = BG;
  printf("[%d] (%d) %s", jobp->jid, jobp->pid, jobp->cmdline);
    
  /* $end handout */
  return;
}

/* 
 * do_fg - Execute the builtin fg command
 */
void do_fg(int jid) 
{
  /* $begin handout */
  struct job_t *jobp=NULL;
  
  if (!(jobp = getjobjid(jobs, jid))) {
    printf("%%%d: No such job\n", jid);
    return;
  }
  
  
  if (kill(-(jobp->pid), SIGCONT) < 0)
    unix_error("kill (fg) error");
  jobp->state = FG;
  waitfg(jobp->pid);


  /* $end handout */
  return;
}

/* 
 * waitfg - Block until process pid is no longer the foreground process
 */
void waitfg(pid_t pid)
{
  sigset_t mask;       /* blocked signal mask */
  sigset_t empty;      /* used to unblock all during sigsuspend */
  
  if (sigemptyset(&mask) < 0)
    unix_error("sigemptyset error");
  if (sigemptyset(&empty) < 0)
    unix_error("sigemptyset error");

  if (sigaddset(&mask, SIGCHLD)) 
    unix_error("sigaddset error");
  if (sigaddset(&mask, SIGINT)) 
    unix_error("sigaddset error");
  if (sigaddset(&mask, SIGTSTP)) 
    unix_error("sigaddset error");

  // Block chld, int, and tstp while we check for the foreground process terminating
  if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
    unix_error("sigprocmask error");

  /* $begin handout */
  struct job_t *j = getjobpid(jobs, pid);

  /* The FG job has already completed and been reaped by the handler */
  if (!j) 
  {
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0)
      unix_error("sigprocmask error");
    return;
  }

  /* Wait for process pid to no longer be the foreground process. */
  while (j->pid == pid && j->state == FG)
  {
    sigsuspend(&empty);
    // After sigsuspend wakes up due to a signal arriving,
    // The original (blocked) mask is applied, so we can safely check the job again
  }

  if (verbose)
    printf("waitfg: Process (%d) no longer the fg process\n", pid);

  // Unblock signals
  if (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0)
    unix_error("sigprocmask error");

  /* $end handout */
  return;
}

/*****************
 * Signal handlers
 *****************/

/* 
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.  
 */
void sigchld_handler(int sig) 
{
  /* $begin handout */
  pid_t child_pid;
  int child_jid;
  int status;
  
  if (verbose)
    printf("sigchld_handler: entering\n");

  /* Detect any terminated or stopped jobs, but don't wait on the others. */ 
  while ((child_pid = waitpid(-1, &status, WNOHANG|WUNTRACED)) > 0) { 
  //while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) { 

    /* Was the job stopped by the receipt of a signal? */
    if (WIFSTOPPED(status)) {
      struct job_t *j = getjobpid(jobs, child_pid);
      if (!j) {
	printf("Lost track of (%d)\n", child_pid);
	return;
      }
      j->state = ST;

      sio_puts("Job [");
      sio_putl(pid2jid(child_pid));
      sio_puts("] (");
      sio_putl(child_pid);
      sio_puts(") stopped by signal ");
      sio_putl(WSTOPSIG(status));
      sio_puts("\n");
	    
      //fprintf(stdout, "Job [%d] (%d) stopped by signal %d\n",
      //      pid2jid(child_pid), child_pid, WSTOPSIG(status));
    }

    /* Was the job terminated by the receipt of an uncaught signal? */
    else if (WIFSIGNALED(status)) { 
      child_jid = pid2jid(child_pid);
      if (deletejob(jobs, child_pid))
	if (verbose)
	  printf("sigchld_handler: Job [%d] (%d) deleted\n", 
		 child_jid, child_pid);
	
      sio_puts("Job [");
      sio_putl(child_jid);
      sio_puts("] (");
      sio_putl(child_pid);
      sio_puts(") terminated by signal ");
      sio_putl(WTERMSIG(status));
      sio_puts("\n");
      //fprintf(stdout, "Job [%d] (%d) terminated by signal %d\n", 
      //      child_jid, child_pid, WTERMSIG(status));

    }

    /* Did the job terminate normally? */
    else if (WIFEXITED(status)) {
      child_jid = pid2jid(child_pid);
      if (deletejob(jobs, child_pid))
	if (verbose)
	  printf("sigchld_handler: Job [%d] (%d) deleted\n", 
		 child_jid,  child_pid);
      if (verbose) {
	printf("sigchld_handler: Job [%d] (%d) terminates OK (status %d)\n", 
	       child_jid, child_pid, WEXITSTATUS(status));
      }
    }
    else 
      unix_error("waitpid error");
  }

  /* 
   * Check for normal termination of the waitpid loop: Either 
   * there were children, but no zombies (child_pid == 0), or there 
   * were no children at all (child_pid == -1 and errno == ECHILD).
   */
  if (!((child_pid == 0) || (child_pid == -1 && errno == ECHILD)))
    unix_error("sigchld_handler wait error");

  if (verbose)
    printf("sigchld_handler: exiting\n");

  /* $end handout */
  return;
}

/* 
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.  
 */
void sigint_handler(int sig) 
{
  /* $begin handout */
  pid_t pid;

  if (verbose)
    printf("sigint_handler: entering\n");
  if ((pid = fgpid(jobs)) > 0) {
    if (kill(-pid, SIGINT) < 0)
      unix_error("kill (sigint) error");
    if (verbose)
      printf("sigint_handler: Job (%d) killed\n", pid);
  }
  if (verbose)
    printf("sigint_handler: exiting\n");
  /* $end handout */
  return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.  
 */
void sigtstp_handler(int sig) 
{
  /* $begin handout */
  pid_t pid;
    
  if (verbose)
    printf("sigtstp_handler: entering\n");
  if ((pid = fgpid(jobs)) > 0) {
    if (kill(-pid, SIGTSTP) < 0)
      unix_error("kill (tstp) error");
    if (verbose)
      printf("sigtstp_handler: Job [%d] (%d) stopped\n", 
	     pid2jid(pid), pid);
  }
  if (verbose)
    printf("sigtstp_handler: exiting\n");
  /* $end handout */
  return;
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
  job->pid = 0;
  job->jid = 0;
  job->state = UNDEF;
  job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
  int i;

  for (i = 0; i < MAXJOBS; i++)
    clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs) 
{
  int i, max=0;

  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].jid > max)
      max = jobs[i].jid;
  return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline) 
{
  int i;
    
  if (pid < 1)
    return 0;

  for (i = 0; i < MAXJOBS; i++) {
    if (jobs[i].pid == 0) {
      jobs[i].pid = pid;
      jobs[i].state = state;
      jobs[i].jid = nextjid++;
      if (nextjid > MAXJOBS)
	nextjid = 1;
      strcpy(jobs[i].cmdline, cmdline);
      if(verbose){
	printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
      }
      return 1;
    }
  }
  printf("Tried to create too many jobs\n");
  return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid) 
{
  int i;

  if (pid < 1)
    return 0;

  for (i = 0; i < MAXJOBS; i++) {
    if (jobs[i].pid == pid) {
      clearjob(&jobs[i]);
      nextjid = maxjid(jobs)+1;
      return 1;
    }
  }
  return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
  int i;

  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].state == FG)
      return jobs[i].pid;
  return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
  int i;

  if (pid < 1)
    return NULL;
  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].pid == pid)
      return &jobs[i];
  return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid) 
{
  int i;

  if (jid < 1)
    return NULL;
  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].jid == jid)
      return &jobs[i];
  return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid) 
{
  int i;

  if (pid < 1)
    return 0;
  for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].pid == pid) {
      return jobs[i].jid;
    }
  return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs) 
{
  int i;
  
  for (i = 0; i < MAXJOBS; i++) {
    if (jobs[i].pid != 0) {
      printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
      switch (jobs[i].state) {
      case BG: 
	printf("Running ");
	break;
      case FG: 
	printf("Foreground ");
	break;
      case ST: 
	printf("Stopped ");
	break;
      default:
	printf("listjobs: Internal error: job[%d].state=%d ", 
	       i, jobs[i].state);
      }
      printf("%s", jobs[i].cmdline);
    }
  }
}
/******************************
 * end job list helper routines
 ******************************/


/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void) 
{
  printf("Usage: shell [-hvp]\n");
  printf("   -h   print this message\n");
  printf("   -v   print additional diagnostic information\n");
  printf("   -p   do not emit a command prompt\n");
  exit(1);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
  fprintf(stdout, "%s: %s\n", msg, strerror(errno));
  exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
  fprintf(stdout, "%s\n", msg);
  exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler) 
{
  struct sigaction action, old_action;

  action.sa_handler = handler;  
  sigemptyset(&action.sa_mask); /* block sigs of type being handled */
  action.sa_flags = SA_RESTART; /* restart syscalls if possible */

  if (sigaction(signum, &action, &old_action) < 0)
    unix_error("Signal error");
  return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig) 
{
  sio_puts("Terminating after receipt of SIGQUIT signal\n");
  exit(1);
}

/* $end tshref-ans */



/* Put string */
ssize_t sio_puts(char s[]) 
{
  return write(STDOUT_FILENO, s, sio_strlen(s)); 
}

/* Put long */
ssize_t sio_putl(long v) 
{
  char s[128];
    
  sio_ltoa(v, s, 10); /* Based on K&R itoa() */  
  return sio_puts(s);
}

/* sio_strlen - Return length of string (from K&R) */
static size_t sio_strlen(char s[])
{
  int i = 0;

  while (s[i] != '\0')
    ++i;
  return i;
}

/* sio_ltoa - Convert long to base b string (from K&R) */
static void sio_ltoa(long v, char s[], int b) 
{
  int c, i = 0;
  int neg = v < 0;

  if (neg)
    v = -v;

  do {  
    s[i++] = ((c = (v % b)) < 10)  ?  c + '0' : c - 10 + 'a';
  } while ((v /= b) > 0);

  if (neg)
    s[i++] = '-';

  s[i] = '\0';
  sio_reverse(s);
}

/* sio_reverse - Reverse a string (from K&R) */
static void sio_reverse(char s[])
{
  int c, i, j;

  for (i = 0, j = strlen(s)-1; i < j; i++, j--) {
    c = s[i];
    s[i] = s[j];
    s[j] = c;
  }
}
