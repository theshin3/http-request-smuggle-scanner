package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class WordRecorder implements IScannerCheck{
    private ConcurrentHashMap.KeySetView<String, Boolean> savedWords = ConcurrentHashMap.newKeySet();
    String wordRegex = "[^a-zA-Z]";
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        savedWords.addAll(Arrays.asList(Utils.callbacks.getHelpers().bytesToString(baseRequestResponse.getRequest()).split(wordRegex)));
        savedWords.addAll(Arrays.asList(Utils.callbacks.getHelpers().bytesToString(baseRequestResponse.getRequest()).split(wordRegex)));
        return new ArrayList<>();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<>();
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
