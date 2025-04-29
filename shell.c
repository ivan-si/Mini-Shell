#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <limits.h>

#define MAX_ARGS 64
#define MAX_COMMAND_LENGTH 1024
#define MAX_PATH_LENGTH PATH_MAX
#define HISTORY_SIZE 20

// Function prototypes
void execute_command(char **args);
void parse_input(char *input, char **args);
int handle_builtin_commands(char **args);
void display_prompt();
char *get_username();
char *get_current_directory();
void handle_redirect(char **args);
void handle_pipe(char **args);
void add_to_history(char *command);
void display_history();

// Global variables
char *command_history[HISTORY_SIZE];
int history_count = 0;

int main() {
    char input[MAX_COMMAND_LENGTH];
    char *args[MAX_ARGS];
    
    // Initialize command history
    for (int i = 0; i < HISTORY_SIZE; i++) {
        command_history[i] = NULL;
    }
    
    // Display welcome message
    printf("Welcome to MyShell! Type 'help' for available commands.\n");
    
    while (1) {
        // Display prompt
        display_prompt();
        
        // Read input
        if (fgets(input, MAX_COMMAND_LENGTH, stdin) == NULL) {
            // Handle EOF (Ctrl+D)
            printf("\nExiting shell. Goodbye!\n");
            break;
        }
        
        // Remove trailing newline character
        input[strcspn(input, "\n")] = 0;
        
        // Skip empty commands
        if (strlen(input) == 0) {
            continue;
        }
        
        // Add command to history
        add_to_history(strdup(input));
        
        // Parse the input
        parse_input(input, args);
        
        // If no command was entered, continue
        if (args[0] == NULL) {
            continue;
        }
        
        // Handle built-in commands
        if (handle_builtin_commands(args)) {
            continue;
        }
        
        // Execute the command
        execute_command(args);
    }
    
    // Free memory allocated for history
    for (int i = 0; i < HISTORY_SIZE; i++) {
        if (command_history[i] != NULL) {
            free(command_history[i]);
        }
    }
    
    return 0;
}

void parse_input(char *input, char **args) {
    char *token;
    int i = 0;
    
    // Handle quotes and special characters
    int in_quotes = 0;
    char *current_pos = input;
    char current_token[MAX_COMMAND_LENGTH] = "";
    int token_index = 0;
    
    while (*current_pos != '\0' && i < MAX_ARGS - 1) {
        if (*current_pos == '"' && (current_pos == input || *(current_pos - 1) != '\\')) {
            in_quotes = !in_quotes;
            current_pos++;
            continue;
        }
        
        if ((*current_pos == ' ' || *current_pos == '\t') && !in_quotes) {
            if (token_index > 0) {
                current_token[token_index] = '\0';
                args[i++] = strdup(current_token);
                token_index = 0;
            }
            current_pos++;
            continue;
        }
        
        // Handle escape sequences
        if (*current_pos == '\\' && *(current_pos + 1) != '\0') {
            current_pos++;
        }
        
        current_token[token_index++] = *current_pos++;
    }
    
    // Add the last token if any
    if (token_index > 0) {
        current_token[token_index] = '\0';
        args[i++] = strdup(current_token);
    }
    
    args[i] = NULL;  // Set the last argument to NULL as required
}

int handle_builtin_commands(char **args) {
    if (args[0] == NULL) {
        return 1;
    }
    
    // exit command
    if (strcmp(args[0], "exit") == 0) {
        printf("Exiting shell. Goodbye!\n");
        exit(0);
    }
    
    // cd command
    if (strcmp(args[0], "cd") == 0) {
        if (args[1] == NULL) {
            // Change to home directory if no argument
            const char *home_dir = getenv("HOME");
            if (home_dir == NULL) {
                struct passwd *pw = getpwuid(getuid());
                home_dir = pw->pw_dir;
            }
            if (chdir(home_dir) != 0) {
                perror("cd failed");
            }
        } else {
            if (chdir(args[1]) != 0) {
                perror("cd failed");
            }
        }
        return 1;
    }
    
    // pwd command
    if (strcmp(args[0], "pwd") == 0) {
        char cwd[MAX_PATH_LENGTH];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("%s\n", cwd);
        } else {
            perror("pwd failed");
        }
        return 1;
    }
    
    // help command
    if (strcmp(args[0], "help") == 0) {
        printf("Available built-in commands:\n");
        printf("  exit           - Exit the shell\n");
        printf("  cd [directory] - Change directory\n");
        printf("  pwd            - Print current working directory\n");
        printf("  help           - Display this help message\n");
        printf("  history        - Display command history\n");
        printf("  clear          - Clear the screen\n");
        return 1;
    }
    
    // history command
    if (strcmp(args[0], "history") == 0) {
        display_history();
        return 1;
    }
    
    // clear command
    if (strcmp(args[0], "clear") == 0) {
        printf("\033[H\033[J");  // ANSI escape sequence to clear screen
        return 1;
    }
    
    return 0;  // Not a built-in command
}

void execute_command(char **args) {
    // Check for redirection
    for (int i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], ">") == 0 || strcmp(args[i], "<") == 0 || 
            strcmp(args[i], ">>") == 0) {
            handle_redirect(args);
            return;
        }
        
        if (strcmp(args[i], "|") == 0) {
            handle_pipe(args);
            return;
        }
    }
    
    // Check for background process with &
    int run_in_background = 0;
    int i;
    for (i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], "&") == 0) {
            run_in_background = 1;
            args[i] = NULL;  // Remove & from arguments
            break;
        }
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return;
    } else if (pid == 0) {
        // Child process
        execvp(args[0], args);
        // If execvp returns, an error occurred
        fprintf(stderr, "Command not found: %s\n", args[0]);
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        if (!run_in_background) {
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                fprintf(stderr, "Command exited with status %d\n", WEXITSTATUS(status));
            }
        } else {
            printf("[%d] Background process started\n", pid);
        }
    }
    
    // Free memory allocated in parse_input
    for (i = 0; args[i] != NULL; i++) {
        free(args[i]);
    }
}

void handle_redirect(char **args) {
    int i;
    int in_redirect = 0, out_redirect = 0, append_redirect = 0;
    char *infile = NULL, *outfile = NULL;
    
    // Find redirection symbols and associated files
    for (i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], "<") == 0) {
            in_redirect = 1;
            if (args[i+1] != NULL) {
                infile = args[i+1];
                args[i] = NULL;
            }
        } else if (strcmp(args[i], ">") == 0) {
            out_redirect = 1;
            if (args[i+1] != NULL) {
                outfile = args[i+1];
                args[i] = NULL;
            }
        } else if (strcmp(args[i], ">>") == 0) {
            append_redirect = 1;
            if (args[i+1] != NULL) {
                outfile = args[i+1];
                args[i] = NULL;
            }
        }
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        return;
    } else if (pid == 0) {
        // Child process
        
        // Handle input redirection
        if (in_redirect) {
            FILE *fp = fopen(infile, "r");
            if (fp == NULL) {
                perror("Input redirection failed");
                exit(EXIT_FAILURE);
            }
            dup2(fileno(fp), STDIN_FILENO);
            fclose(fp);
        }
        
        // Handle output redirection
        if (out_redirect) {
            FILE *fp = fopen(outfile, "w");
            if (fp == NULL) {
                perror("Output redirection failed");
                exit(EXIT_FAILURE);
            }
            dup2(fileno(fp), STDOUT_FILENO);
            fclose(fp);
        } else if (append_redirect) {
            FILE *fp = fopen(outfile, "a");
            if (fp == NULL) {
                perror("Output redirection (append) failed");
                exit(EXIT_FAILURE);
            }
            dup2(fileno(fp), STDOUT_FILENO);
            fclose(fp);
        }
        
        execvp(args[0], args);
        // If execvp returns, an error occurred
        fprintf(stderr, "Command not found: %s\n", args[0]);
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        
        // Free memory allocated in parse_input
        for (i = 0; args[i] != NULL; i++) {
            free(args[i]);
        }
    }
}

void handle_pipe(char **args) {
    int i;
    int pipe_index = -1;
    
    // Find the pipe symbol
    for (i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], "|") == 0) {
            pipe_index = i;
            break;
        }
    }
    
    if (pipe_index == -1) {
        return;  // No pipe found
    }
    
    // Split the arguments
    char **cmd1 = args;
    char **cmd2 = &args[pipe_index + 1];
    args[pipe_index] = NULL;
    
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe failed");
        return;
    }
    
    pid_t pid1 = fork();
    
    if (pid1 == -1) {
        perror("fork failed");
        return;
    } else if (pid1 == 0) {
        // Child process 1 (writes to pipe)
        close(pipefd[0]);  // Close read end
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        
        execvp(cmd1[0], cmd1);
        // If execvp returns, an error occurred
        fprintf(stderr, "Command not found: %s\n", cmd1[0]);
        exit(EXIT_FAILURE);
    }
    
    pid_t pid2 = fork();
    
    if (pid2 == -1) {
        perror("fork failed");
        return;
    } else if (pid2 == 0) {
        // Child process 2 (reads from pipe)
        close(pipefd[1]);  // Close write end
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        
        execvp(cmd2[0], cmd2);
        // If execvp returns, an error occurred
        fprintf(stderr, "Command not found: %s\n", cmd2[0]);
        exit(EXIT_FAILURE);
    }
    
    // Parent process
    close(pipefd[0]);
    close(pipefd[1]);
    
    waitpid(pid1, NULL, 0);
    waitpid(pid2, NULL, 0);
    
    // Free memory allocated in parse_input
    for (i = 0; args[i] != NULL; i++) {
        free(args[i]);
    }
}

void display_prompt() {
    char *username = get_username();
    char *cwd = get_current_directory();
    
    printf("\033[1;32m%s\033[0m:\033[1;34m%s\033[0m$ ", username, cwd);
    free(cwd);
}

char *get_username() {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
        return "user";
    }
    return pw->pw_name;
}

char *get_current_directory() {
    char cwd[MAX_PATH_LENGTH];
    char *home_dir = getenv("HOME");
    char *result;
    
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        result = strdup("unknown");
        return result;
    }
    
    // Replace home directory with ~
    if (home_dir != NULL && strncmp(cwd, home_dir, strlen(home_dir)) == 0) {
        result = malloc(strlen(cwd) - strlen(home_dir) + 2);
        if (result == NULL) {
            return strdup(cwd);
        }
        
        result[0] = '~';
        strcpy(result + 1, cwd + strlen(home_dir));
        return result;
    }
    
    return strdup(cwd);
}

void add_to_history(char *command) {
    // Free the oldest command if history is full
    if (history_count == HISTORY_SIZE && command_history[0] != NULL) {
        free(command_history[0]);
        
        // Shift all commands
        for (int i = 1; i < HISTORY_SIZE; i++) {
            command_history[i-1] = command_history[i];
        }
        
        history_count--;
    }
    
    // Add new command to history
    command_history[history_count] = command;
    history_count++;
}

void display_history() {
    for (int i = 0; i < history_count; i++) {
        printf("%d: %s\n", i + 1, command_history[i]);
    }
}
