package com.deeptrace.cli;

import com.deeptrace.classifier.AppType;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class CLIArguments {

    private Path inputFile;
    private Path outputFile;

    private boolean helpRequested;

    private int workerCount = 4;
    private int queueCapacity = 1000;

    private final List<String> blockedIPs = new ArrayList<>();
    private final List<String> blockedDomains = new ArrayList<>();
    private final List<AppType> blockedApplications = new ArrayList<>();

    public Path getInputFile() {
        return inputFile;
    }

    public void setInputFile(Path inputFile) {
        this.inputFile = inputFile;
    }

    public Path getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(Path outputFile) {
        this.outputFile = outputFile;
    }

    public int getWorkerCount() {
        return workerCount;
    }

    public void setWorkerCount(int workerCount) {
        this.workerCount = workerCount;
    }

    public int getQueueCapacity() {
        return queueCapacity;
    }

    public void setQueueCapacity(int queueCapacity) {
        this.queueCapacity = queueCapacity;
    }

    public List<String> getBlockedIPs() {
        return blockedIPs;
    }

    public List<String> getBlockedDomains() {
        return blockedDomains;
    }

    public List<AppType> getBlockedApplications() {
        return blockedApplications;
    }

    public boolean isHelpRequested() {
        return helpRequested;
    }

    public void setHelpRequested(boolean helpRequested) {
        this.helpRequested = helpRequested;
    }
}