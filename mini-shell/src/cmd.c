// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	if (!dir)
		return false;
	return !chdir(dir->string);
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	return SHELL_EXIT; /* TODO: Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int ret;
	/* TODO: Sanity checks. */
	if (!s || !s->verb)
		return 1;
	/* TODO: If builtin command, execute the command. */
	if (!strcmp(s->verb->string, "cd") && (!s->in && !s->out && !s->err))
		return !shell_cd(s->params);
	if (!strcmp(s->verb->string, "exit") || !strcmp(s->verb->string, "quit"))
		return shell_exit();
	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part && !strcmp(s->verb->next_part->string, "=")) {
		char *env_value = get_word(s->verb->next_part->next_part);
		// perform the assignment
		ret = setenv(s->verb->string, env_value, 1);
		free(env_value);
		return ret;
	}
	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t pid_cmd;
	int status_cmd;
	// Fork new process
	pid_cmd = fork();
	DIE(pid_cmd == -1, "fork");
	if (pid_cmd == 0) {
		int fd_stdin = dup(0), fd_stdout = dup(1), fd_stderr = dup(2);
		// Perform redirections in child
		if (s->in) {
			char *string_in = get_word(s->in);
			int flags, fd_in;
			// redirection of input
			flags = O_RDONLY | O_CREAT;
			fd_in = open(string_in, flags, 0644);
			DIE(fd_in < 0, "open");
			dup2(fd_in, 0); close(fd_in);
			free(string_in);
		}
		if (s->out) {
			char *string_out = get_word(s->out);
			int flags, fd_out;
			// redirection of output
			flags = O_WRONLY | O_CREAT | O_TRUNC;
			if (s->err || s->io_flags == IO_OUT_APPEND)
				flags = O_WRONLY | O_CREAT | O_APPEND;
			fd_out = open(string_out, flags, 0644);
			DIE(fd_out < 0, "open");
			dup2(fd_out, 1); close(fd_out);
			free(string_out);
		}
		if (s->err) {
			char *string_err = get_word(s->err);
			int flags, fd_err;
			// redirection of error
			flags = O_WRONLY | O_CREAT;
			if (s->io_flags == IO_ERR_APPEND)
				flags = O_WRONLY | O_CREAT | O_APPEND;
			fd_err = open(string_err, flags, 0644);
			DIE(fd_err < 0, "open");
			dup2(fd_err, 2); close(fd_err);
			free(string_err);
		}
		if (!strcmp(s->verb->string, "cd") && (s->out || s->in || s->err)) {
			dup2(fd_stdin, 0); close(fd_stdin);
			dup2(fd_stdout, 1); close(fd_stdout);
			dup2(fd_stderr, 2); close(fd_stderr);
			return !shell_cd(s->params);
		}
		int cnt = 0;
		char **args = get_argv(s, &cnt);
		// Load executable in child
		ret = execvp(s->verb->string, args);
		free(args);
		dup2(fd_stdin, 0); close(fd_stdin);
		dup2(fd_stdout, 1); close(fd_stdout);
		dup2(fd_stderr, 2); close(fd_stderr);
		if (ret < 0)
			printf("Execution failed for '%s'\n", s->verb->string);
		exit(ret);
	} else {
		// Wait for child
		DIE(waitpid(pid_cmd, &status_cmd, 0) < 0, "waitpid");
	}
	// Return exit status
	return WEXITSTATUS(status_cmd); /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t pid_cmd1, pid_cmd2;
	int status_cmd1, status_cmd2;
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_cmd1 = fork();
	DIE(pid_cmd1 == -1, "fork");
	if (pid_cmd1 == 0) {
		exit(parse_command(cmd1, level + 1, father));
	} else {
		pid_cmd2 = fork();
		DIE(pid_cmd2 == -1, "fork");
		if (pid_cmd2 == 0) {
			exit(parse_command(cmd2, level + 1, father));
		} else {
			DIE(waitpid(pid_cmd1, &status_cmd1, 0) < 0, "waitpid");
			DIE(waitpid(pid_cmd2, &status_cmd2, 0) < 0, "waitpid");
		}
	}
	return WEXITSTATUS(status_cmd1) && WEXITSTATUS(status_cmd2); /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	if (cmd1 == NULL || cmd2 == NULL)
		return true;
	if (cmd2->scmd && !strcmp(cmd2->scmd->verb->string, "false"))
		return true;
	if (cmd2->scmd && !strcmp(cmd2->scmd->verb->string, "true"))
		return false;
	int ret;
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	int pipefds[2]; DIE(pipe(pipefds) == -1, "pipe");
	pid_t pid_cmd1, pid_cmd2;
	int status_cmd1, status_cmd2;
	// Fork new process
	pid_cmd1 = fork();
	DIE(pid_cmd1 == -1, "fork");
	if (pid_cmd1 == 0) {
		int fd_stdout = dup(1);
		// output redirection
		dup2(pipefds[WRITE], 1); close(pipefds[READ]); close(pipefds[WRITE]);
		ret = parse_command(cmd1, level + 1, father);
		dup2(fd_stdout, 1); close(fd_stdout);
		if (ret < 0)
			return false;
		exit(ret);
	} else {
		pid_cmd2 = fork();
		DIE(pid_cmd2 == -1, "fork");
		if (pid_cmd2 == 0) {
			int fd_stdin = dup(0);
			// input redirection
			dup2(pipefds[READ], 0); close(pipefds[READ]); close(pipefds[WRITE]);
			ret = parse_command(cmd2, level + 1, father);
			dup2(fd_stdin, 0); close(fd_stdin);
			exit(ret);
		} else {
			close(pipefds[READ]); close(pipefds[WRITE]);
			DIE(waitpid(pid_cmd1, &status_cmd1, 0) < 0, "waitpid");
			DIE(waitpid(pid_cmd2, &status_cmd2, 0) < 0, "waitpid");
		}
		close(pipefds[READ]); close(pipefds[WRITE]);
	}
	return WEXITSTATUS(status_cmd1) && WEXITSTATUS(status_cmd2); /* TODO: Replace with actual exit status. */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (!c)
		return shell_exit();
	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		return parse_simple(c->scmd, level, father); /* TODO: Replace with actual exit code of command. */
	}
	int ret = 0;

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		ret = parse_command(c->cmd1, level + 1, c);
		ret = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		ret = run_in_parallel(c->cmd1, c->cmd2, level + 1, c) ? 0 : 1;
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		ret = parse_command(c->cmd1, level + 1, c);
		if (ret != 0)
			ret = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		ret = parse_command(c->cmd1, level + 1, c);
		if (ret == 0)
			ret = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		ret = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return ret; /* TODO: Replace with actual exit code of command. */
}
