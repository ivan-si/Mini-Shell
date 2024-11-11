#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

#define MAX_ARGS 20
#define MAX_COMMAND_LENGTH 100

void execute_command(char *command, char **args);
void parse_input(char *input, char **args);

int main() {
    char input[MAX_COMMAND_LENGTH];
    char *args[MAX_ARGS];

    while (1) {
        printf("myshell :)");
        fgets(input, MAX_COMMAND_LENGTH, stdin);

        // Remove trailing newline character
        input[strcspn(input, "\n")] = 0;

        // Parse the input
        parse_input(input, args);

        // Check for built-in commands
        if (strcmp(args[0], "exit") == 0) {
            exit(0);
        }

        // Execute the command
        execute_command(args[0], args);
    }

    return 0;
}

void parse_input(char *input, char **args) {
    char *token = strtok(input, " ");
    int i = 0;
    while (token != NULL && i < MAX_ARGS - 1) {
        args[i] = token;
        token = strtok(NULL, " ");
        i++;
    }
    args[i] = NULL;  // Set the last argument to NULL as required
}

void execute_command(char *command, char **args) {
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execvp(command, args);
        // If execvp returns, an error occurred
        perror("exec failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
    }
}
