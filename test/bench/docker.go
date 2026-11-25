package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// docker runs the docker CLI and returns its trimmed stdout.
func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// container is a running, CPU-pinned container on the host network.
type container struct {
	name string
	cpus int
}

// startContainer replaces any container with the same name. args go between
// "docker run" options and the image (mounts, entrypoint); cmd follows it.
func startContainer(ctx context.Context, name, cpuset string, ncpu int, image string, args, cmd []string) (*container, error) {
	docker(ctx, "rm", "-f", name)
	run := []string{"run", "-d", "--name", name, "--network", "host",
		"--cpuset-cpus", cpuset, "--ulimit", "nofile=65535:65535"}
	run = append(run, args...)
	run = append(run, image)
	run = append(run, cmd...)
	if _, err := docker(ctx, run...); err != nil {
		return nil, err
	}
	return &container{name: name, cpus: ncpu}, nil
}

func (c *container) stop(ctx context.Context) {
	docker(context.WithoutCancel(ctx), "rm", "-f", c.name)
}

func (c *container) logs(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", "20", c.name)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

// cpuUsec returns the CPU time the container's cgroup has used so far.
func (c *container) cpuUsec(ctx context.Context) (int64, error) {
	out, err := docker(ctx, "exec", c.name, "cat", "/sys/fs/cgroup/cpu.stat")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(out, "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			return strconv.ParseInt(v, 10, 64)
		}
	}
	return 0, fmt.Errorf("%s: no usage_usec in cpu.stat", c.name)
}

// memBytes returns the container's current memory use.
func (c *container) memBytes(ctx context.Context) (int64, error) {
	out, err := docker(ctx, "exec", c.name, "cat", "/sys/fs/cgroup/memory.current")
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(out, 10, 64)
}
