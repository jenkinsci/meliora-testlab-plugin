package fi.meliora.testlab.ext.jenkins;

import fi.meliora.testlab.ext.crest.CrestEndpointFactory;
import fi.meliora.testlab.ext.crest.TestResultResource;
import fi.meliora.testlab.ext.rest.model.AddTestResultResponse;
import fi.meliora.testlab.ext.rest.model.KeyValuePair;
import fi.meliora.testlab.ext.rest.model.TestCaseResult;
import hudson.model.AbstractBuild;
import hudson.tasks.junit.CaseResult;
import hudson.tasks.junit.SuiteResult;
import hudson.tasks.test.AbstractTestResultAction;
import hudson.tasks.test.AggregatedTestResultAction;
import hudson.tasks.test.TestResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sends jenkins test results to Testlab.
 *
 * @author Marko Kanala, Meliora Ltd
 */
public class Sender {
    /**
     * Jenkins uses java.util.logging for loggers. Configure Testlab plugin specific
     * log to your Jenkins from Manage Jenkins > System Log and add a new logger
     * for class fi.meliora.testlab.ext.jenkins.Sender with ALL level.
     */
    private final static Logger log = Logger.getLogger(Sender.class.getName());

    static {
        //
        // set crest to prefer slf4j, see http://crest.codegist.org/deeper/logging.html
        //
        System.getProperties().setProperty(
                "org.codegist.common.log.class",
                "org.codegist.common.log.Slf4jLogger"
        );
    }

    /**
     * Does the actual sending of results to Testlab. Called from appropriate Jenkins extension point.
     *
     * @param companyId
     * @param usingonpremise
     * @param onpremiseurl
     * @param apiKey
     * @param projectKey
     * @param milestone
     * @param testRunTitle
     * @param comment
     * @param testTargetTitle
     * @param testEnvironmentTitle
     * @param tags
     * @param parameters
     * @param addIssues
     * @param mergeAsSingleIssue
     * @param reopenExisting
     * @param assignToUser
     * @param testCaseMappingField
     * @param build
     */
    public static void sendResults(String companyId, boolean usingonpremise, String onpremiseurl, String apiKey, String projectKey, String milestone, String testRunTitle, String comment, String testTargetTitle, String testEnvironmentTitle, String tags, Map<String, String> parameters, boolean addIssues, boolean mergeAsSingleIssue, boolean reopenExisting, String assignToUser, String testCaseMappingField, AbstractBuild<?, ?> build) {
        // no need to validate params here, extension ensures we have some values set

        if(log.isLoggable(Level.FINE))
            log.fine("Running Sender - " + companyId + ", " + usingonpremise + ", " + onpremiseurl + ", api key hidden, " + projectKey + ", " + milestone + ", " + testRunTitle + ", " + comment + ", " + testTargetTitle + ", " + testEnvironmentTitle + ", " + tags + ", [" + parameters + "], " + addIssues + ", " + mergeAsSingleIssue + ", " + reopenExisting + ", " + assignToUser + ", " + testCaseMappingField);

        // parse test results
        AbstractTestResultAction ra = build.getAction(AbstractTestResultAction.class);

        if(log.isLoggable(Level.FINE))
            log.fine("Have results: " + ra);

        if(ra == null) {
            log.warning("We have no results to publish. Please make sure your job is configured to publish some test results to make them available to this plugin.");
        } else {
            List<TestCaseResult> results = new ArrayList<TestCaseResult>();

            String user = "Jenkins job: " + build.getProject().getDisplayName();

            fi.meliora.testlab.ext.rest.model.TestResult data = new fi.meliora.testlab.ext.rest.model.TestResult();
            data.setStatus(fi.meliora.testlab.ext.rest.model.TestResult.STATUS_FINISHED);
            data.setProjectKey(projectKey);
            data.setTestRunTitle(testRunTitle);
            // note: we send the set milestone in both fields as backend logic tries first with identifier and fallbacks to title
            data.setMilestoneIdentifier(milestone);
            data.setMilestoneTitle(milestone);
            data.setAddIssues(addIssues);
            data.setMergeAsSingleIssue(mergeAsSingleIssue);
            data.setReopenExistingIssues(reopenExisting);
            data.setAssignIssuesToUser(assignToUser);
            data.setTestCaseMappingField(testCaseMappingField);
            data.setUser(user);
            data.setComment(comment);
            if(parameters != null && parameters.size() > 0) {
                List<KeyValuePair> parameterValues = new ArrayList<KeyValuePair>();
                for(String name : parameters.keySet()) {
                    KeyValuePair kvp = new KeyValuePair();
                    kvp.setKey(name);
                    kvp.setValue(parameters.get(name));
                    parameterValues.add(kvp);
                    if(log.isLoggable(Level.FINE))
                        log.fine("Sending test case parameter " + name + " with value " + kvp.getValue());
                }
                data.setParameters(parameterValues);
            }

            if(!TestlabNotifier.isBlank(testTargetTitle))
                data.setTestTargetTitle(testTargetTitle);

            if(!TestlabNotifier.isBlank(testEnvironmentTitle))
                data.setTestEnvironmentTitle(testEnvironmentTitle);

            if(!TestlabNotifier.isBlank(tags)) {
                data.setTags(tags);
            }

            Object resultObject = ra.getResult();
            if(resultObject instanceof List) {
                List childReports = (List)resultObject;
                for(Object childReport : childReports) {
                    if(childReport instanceof AggregatedTestResultAction.ChildReport) {
                        Object childResultObject = ((AggregatedTestResultAction.ChildReport) childReport).result;
                        if(log.isLoggable(Level.FINE))
                            log.fine("Have child results: " + childResultObject);
                        parseResult(build, childResultObject, results, user);
                    }
                }
            } else {
                parseResult(build, resultObject, results, user);
            }

            if(results.size() > 0) {
                if(log.isLoggable(Level.FINE))
                    log.fine("Sending " + results.size() + " test results to Testlab.");
                data.setResults(results);

                // send results to testlab
                String onpremiseUrl = usingonpremise ? onpremiseurl : null;
                AddTestResultResponse response = CrestEndpointFactory.getInstance().getTestlabEndpoint(
                        companyId, onpremiseUrl, apiKey, TestResultResource.class
                ).addTestResult(data);

                if(log.isLoggable(Level.INFO))
                    log.info("Posted results successfully to testlab test run: " + response.getTestRunId());
            } else {
                if(log.isLoggable(Level.INFO))
                    log.info("No test results resolved to send to Testlab. Skipping.");
            }
        }
    }

    protected static void parseResult(AbstractBuild<?, ?> build, Object resultObject, final List<TestCaseResult> results, String user) {
        if(resultObject instanceof hudson.tasks.test.TestResult) {
            TestResult result = (TestResult)resultObject;
            if(log.isLoggable(Level.FINE))
                log.fine("Result object: " + result + ", " + result.getClass().getName());

            // parse results
            if(result instanceof hudson.tasks.junit.TestResult) {

                //// junit results

                if(log.isLoggable(Level.FINE))
                    log.fine("Detected junit compatible result object.");

                hudson.tasks.junit.TestResult junitResult = (hudson.tasks.junit.TestResult)result;

                for(SuiteResult sr : junitResult.getSuites()) {
                    for(CaseResult cr : sr.getCases()) {
                        String id = cr.getClassName() + "." + cr.getName();
                        if(log.isLoggable(Level.FINE))
                            log.fine("Status for " + id + " is " + cr.getStatus());
                        int res;
                        if(cr.isPassed())
                            res = TestCaseResult.RESULT_PASS;
                        else if(cr.isSkipped())
                            res = TestCaseResult.RESULT_SKIP;
                        else
                            res = TestCaseResult.RESULT_FAIL;

                        String msg = cr.getErrorDetails();
                        String stacktrace = cr.getErrorStackTrace();

                        results.add(getTestCaseResult(build, id, res, msg, stacktrace, user, cr.getDuration()));
                    }
                }
            } else {

                //// a generic test result, try to parse it
                //
                // this should work for example with testng harness
                // see https://github.com/jenkinsci/testng-plugin-plugin/blob/master/src/main/java/hudson/plugins/testng/results/MethodResult.java

                if(log.isLoggable(Level.FINE))
                    log.fine("Detected generic result object.");

                for(TestResult tr : result.getPassedTests()) {
                    String id = tr.getParent() != null ? tr.getParent().getName() + "." + tr.getName() : tr.getName();
                    results.add(getTestCaseResult(build, id, TestCaseResult.RESULT_PASS, tr.getErrorDetails(), tr.getErrorStackTrace(), user, tr.getDuration()));
                }
                for(TestResult tr : result.getFailedTests()) {
                    String id = tr.getParent() != null ? tr.getParent().getName() + "." + tr.getName() : tr.getName();
                    results.add(getTestCaseResult(build, id, TestCaseResult.RESULT_FAIL, tr.getErrorDetails(), tr.getErrorStackTrace(), user, tr.getDuration()));
                }
                for(TestResult tr : result.getSkippedTests()) {
                    String id = tr.getParent() != null ? tr.getParent().getName() + "." + tr.getName() : tr.getName();
                    results.add(getTestCaseResult(build, id, TestCaseResult.RESULT_SKIP, tr.getErrorDetails(), tr.getErrorStackTrace(), user, tr.getDuration()));
                }
            }
        }
    }

    protected static TestCaseResult getTestCaseResult(AbstractBuild<?, ?> build, String id, int result, String msg, String stacktrace, String user, float duration) {
        TestCaseResult r = new TestCaseResult();
        r.setMappingId(id);
        r.setResult(result);
        long started = build.getTimeInMillis();
        r.setStarted(started);
        r.setRun(started + (long)(duration * 1000));        // duration as float in seconds
        r.setRunBy(user);
        if(msg != null || stacktrace != null) {
            StringBuilder comment = new StringBuilder();
            if(!TestlabNotifier.isBlank(msg)) {
                comment.append(msg);
            }
            if(!TestlabNotifier.isBlank(stacktrace)) {
                if(comment.length() > 0)
                    comment.append("\n\n");
                comment.append(stacktrace);
            }
            r.setComment(comment.toString());
        }
        return r;
    }

}
