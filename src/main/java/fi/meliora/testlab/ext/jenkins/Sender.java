package fi.meliora.testlab.ext.jenkins;

import fi.meliora.testlab.ext.crest.CrestEndpointFactory;
import fi.meliora.testlab.ext.crest.TestResultResource;
import fi.meliora.testlab.ext.rest.model.*;
import hudson.AbortException;
import hudson.FilePath;
import hudson.Util;
import hudson.model.Action;
import hudson.model.Run;
import hudson.remoting.VirtualChannel;
import hudson.tasks.junit.CaseResult;
import hudson.tasks.junit.SuiteResult;
import hudson.tasks.test.AbstractTestResultAction;
import hudson.tasks.test.AggregatedTestResultAction;
import hudson.tasks.test.TestResult;
import jenkins.MasterToSlaveFileCallable;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.tools.ant.DirectoryScanner;
import org.apache.tools.ant.types.FileSet;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sends jenkins test results to Testlab.
 *
 * @author Meliora Ltd
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
     * @param tapTestsAsSteps,
     * @param tapFileNameInIdentifier,
     * @param workspace
     * @param companyId
     * @param usingonpremise
     * @param onpremiseurl
     * @param apiKey
     * @param projectKey
     * @param ruleset
     * @param milestone
     * @param testRunTitle
     * @param description
     * @param testTargetTitle
     * @param testEnvironmentTitle
     * @param tags
     * @param parameters
     * @param addIssueStrategy
     * @param reopenExisting
     * @param assignToUser
     * @param publishTap
     * @param tapTestNumberInIdentifier
     * @param publishRobot
     * @param robotOutput
     * @param robotCatenateParentKeywords
     * @param automationSource
     * @param resultName
     * @param culprits
     * @param changesets
     * @param build
     */
    public static void sendResults(final FilePath workspace, String companyId, boolean usingonpremise, String onpremiseurl, String apiKey, String projectKey, String ruleset, String milestone,
                                   String testRunTitle, String description, String testTargetTitle, String testEnvironmentTitle, String tags,
                                   Map<String, String> parameters, fi.meliora.testlab.ext.rest.model.TestResult.AddIssueStrategy addIssueStrategy, Boolean reopenExisting, String assignToUser,
                                   boolean publishTap, boolean tapTestsAsSteps, boolean tapFileNameInIdentifier, boolean tapTestNumberInIdentifier, String tapMappingPrefix,
                                   boolean publishRobot, String robotOutput, Boolean robotCatenateParentKeywords,
                                   String automationSource, String resultName, List<String> culprits, List<Changeset> changesets, Run<?, ?> build) {

        // no need to validate params here, extension ensures we have some values set

        if(log.isLoggable(Level.FINE))
            log.fine("Running Sender - " + companyId + ", " + usingonpremise + ", " + onpremiseurl + ", api key hidden, " + projectKey + ", " + ruleset + ", " + milestone
                    + ", " + testRunTitle + ", " + description + ", " + testTargetTitle + ", " + testEnvironmentTitle + ", " + tags + ", [" + parameters + "], "
                    + addIssueStrategy + ", " + reopenExisting + ", " + assignToUser
                    + ", " + publishTap + ", " + tapTestsAsSteps + ", " + tapFileNameInIdentifier + ", " + tapTestNumberInIdentifier + ", " + tapMappingPrefix
                    + ", " + publishRobot + ", " + robotOutput + ", " + robotCatenateParentKeywords + ", " + automationSource
            );

        if(log.isLoggable(Level.FINE))
            log.fine("tap-plugin installed ? : " + (hasTAPSupport() ? "Yes, we have TAP support." : "No, no TAP support available."));

        //// parse test results

        boolean hasTAPSupport = hasTAPSupport();
        List<Object> ras = new ArrayList<Object>();
        for(Action a : build.getAllActions()) {
            if(log.isLoggable(Level.FINE))
                log.fine("Action: " + a);
            if (hasTAPSupport && a instanceof org.tap4j.plugin.TapTestResultAction) {
                ras.add(a);
            } else if (a instanceof AbstractTestResultAction) {
                ras.add(a);
            }
        }
        
        if(log.isLoggable(Level.FINE))
            log.fine("Have results: " + ras);

        String robotXml = null;
        if(publishRobot) {
            try {
                robotXml = workspace.act(new RobotOutputCallable(robotOutput));
                log.fine("Found robot output xml: " + robotXml);
            } catch (Exception e) {
                log.severe("Could not parse Robot Framework's output.xml: " + e.getMessage());
                throw new RuntimeException(e);
            }
        }

        if(ras.isEmpty() && (publishRobot && robotXml == null)) {
            log.warning("We have no results to publish. Please make sure your job is configured to publish some test results to make them available to this plugin.");
        } else {
            String user = "Jenkins job: " + build.getParent().getDisplayName();

            fi.meliora.testlab.ext.rest.model.TestResult data = new fi.meliora.testlab.ext.rest.model.TestResult();
            data.setProjectKey(projectKey);
            data.setRuleset(ruleset);
            data.setAutomationSourceTitle(automationSource);
            data.setTestRunTitle(testRunTitle);
            // note: we send the set milestone in both fields as backend logic tries first with identifier and fallbacks to title
            data.setMilestoneIdentifier(milestone);
            data.setMilestoneTitle(milestone);
            data.setAddIssueStrategy(addIssueStrategy);
            data.setReopenExistingIssues(reopenExisting);
            data.setAssignIssuesToUser(assignToUser);
            data.setUser(user);
            data.setDescription(description);
            data.setResultName(resultName);
            data.setCulprits(culprits);
            data.setChangesets(changesets);

            if(parameters != null && !parameters.isEmpty()) {
                List<KeyValuePair> parameterValues = new ArrayList<KeyValuePair>();
                for(Map.Entry<String, String> entry : parameters.entrySet()) {
                    KeyValuePair kvp = new KeyValuePair();
                    kvp.setKey(entry.getKey());
                    kvp.setValue(entry.getValue());
                    parameterValues.add(kvp);
                    if(log.isLoggable(Level.FINE))
                        log.fine("Sending test case parameter " + entry.getKey() + " with value " + kvp.getValue());
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

            boolean hadResults = false;
            List<TestCaseResult> results = new ArrayList<TestCaseResult>();

            for(Object ra : ras) {
                Object resultObject = null;
                if(hasTAPSupport && ra instanceof org.tap4j.plugin.TapTestResultAction) {
                    try {
                        // due to 2.1 change in tap plugin, try to keep compatibility to tap plugin < 2.1
                        Method m = ra.getClass().getMethod("getResult");
                        resultObject = m.invoke(ra);
                    } catch (Exception e) {
                        log.fine("Could not resolve TapTestResultAction result: " + e.getMessage());
                    }
                } else if(ra instanceof AbstractTestResultAction) {
                    resultObject = ((AbstractTestResultAction<?>)ra).getResult();
                }
                if(resultObject != null) {
                    if (resultObject instanceof List) {
                        List childReports = (List) resultObject;
                        for (Object childReport : childReports) {
                            if (childReport instanceof AggregatedTestResultAction.ChildReport) {
                                Object childResultObject = ((AggregatedTestResultAction.ChildReport) childReport).result;
                                if (log.isLoggable(Level.FINE))
                                    log.fine("Have child results: " + childResultObject);
                                parseResult(build, childResultObject, results, user, publishTap, tapTestsAsSteps, tapFileNameInIdentifier, tapTestNumberInIdentifier, tapMappingPrefix);
                            }
                        }
                    } else {
                        parseResult(build, resultObject, results, user, publishTap, tapTestsAsSteps, tapFileNameInIdentifier, tapTestNumberInIdentifier, tapMappingPrefix);
                    }
                }
            }

            if (!results.isEmpty()) {
                if (log.isLoggable(Level.FINE))
                    log.fine("Sending " + results.size() + " test results to Testlab.");
                data.setResults(results);

                hadResults = true;
            }

            if(publishRobot && robotXml != null) {
                data.setRobotCatenateParentKeywords(robotCatenateParentKeywords);
                data.setXmlFormat(fi.meliora.testlab.ext.rest.model.TestResult.FORMAT_ROBOTFRAMEWORK);
                data.setXml(robotXml);

                if(log.isLoggable(Level.FINE))
                    log.fine("Including robot framework test results to be sent to Testlab.");

                hadResults = true;
            }

            if(hadResults) {
                // send results to testlab
                String onpremiseUrl = usingonpremise ? onpremiseurl : null;

                AddTestResultResponse response = null;
                if(!"true".equalsIgnoreCase(System.getProperty("TESTLAB_SENDER_SKIP_SEND"))) {
                    response = CrestEndpointFactory.getInstance().getTestlabEndpoint(
                            companyId, onpremiseUrl, apiKey, TestResultResource.class
                    ).addTestResult(data);
                }

                if(log.isLoggable(Level.INFO))
                    log.info("Posted results successfully to testlab test run: " + (response != null ? "" + response.getTestRunId() : "TESTLAB_SENDER_SKIP_SEND"));
            } else {
                if(log.isLoggable(Level.INFO))
                    log.info("No test results resolved to send to Testlab. Skipping.");
            }
        }
    }

    protected static void parseResult(Run<?, ?> build, Object resultObject, final List<TestCaseResult> results, String user,
                                      boolean publishTap, boolean tapTestsAsSteps, boolean tapFileNameInIdentifier, boolean tapTestNumberInIdentifier, String tapMappingPrefix) {
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
            } else if (hasTAPSupport() && publishTap && result instanceof org.tap4j.plugin.model.TapStreamResult) {

                if(log.isLoggable(Level.FINE))
                    log.fine("Detected tap-plugin result object.");

                org.tap4j.plugin.model.TapStreamResult tsr = (org.tap4j.plugin.model.TapStreamResult)result;

                for(TestResult tr : tsr.getChildren()) {
                    org.tap4j.plugin.model.TapTestResultResult r = (org.tap4j.plugin.model.TapTestResultResult)tr;

                    // see https://testanything.org/tap-specification.html

                    try {
                        //// parse tap test name

                        log.fine("TAP RESULT: " + r);

                        // 18 - 2Flume Version Check
                        String tapTest = r.getTitle();
                        if(!tapTestNumberInIdentifier) {
                            if(tapTest.contains(" - ")) {
                                tapTest = tapTest.substring(tapTest.indexOf(" - ") + 3);
                            }
                        }

                        //// parse tap file name

                        // tapfiles/second-hadoop-components.tap-18
                        String fileName = URLDecoder.decode(r.getSafeName(), "UTF-8");
                        int slash = fileName.lastIndexOf('/');
                        if(slash > -1) {
                            // second-hadoop-components.tap-18
                            fileName = fileName.substring(slash + 1);
                        }
                        // second-hadoop-components.tap
                        fileName = fileName.substring(0, fileName.lastIndexOf('-'));

                        //// determine result

                        int testResult;
                        if("Yes".equals(r.getSkip())) {
                            testResult = TestCaseResult.RESULT_SKIP;
//                        } else if("Yes".equals(r.getTodo())) {
//                            // These tests represent a feature to be implemented or a
//                            // bug to be fixed and act as something of an executable
//                            // "things to do" list. They are not expected to succeed.
//                            // Should a todo test point begin succeeding, the harness
//                            // should report it as a bonus. This indicates that whatever
//                            // you were supposed to do has been done and you should promote
//                            // this to a normal test point.

                            // => we just report the todo directived results by their status

                        } else if("OK".equals(r.getStatus())) {
                            testResult = TestCaseResult.RESULT_PASS;
                        } else {
                            // fail tests by default ("NOT OK")
                            testResult = TestCaseResult.RESULT_FAIL;
                        }

                        log.fine(" TAP test result: " + testResult);

                        if(!tapTestsAsSteps) {
                            //// regular publish, map each tap line to a test case

                            // construct test identifier

                            String id;
                            if(tapFileNameInIdentifier) {
                                id = fileName.replaceAll("\\.", "_") + "." + tapTest;
                            } else {
                                id = tapTest;
                            }
                            if(!StringUtils.isBlank(tapMappingPrefix)) {
                                id = tapMappingPrefix + id;
                            }

                            log.fine(" TAP identifier parsed: " + id);

                            results.add(getTestCaseResult(build, id, testResult, r.toString(), r.getErrorStackTrace(), user, r.getDuration()));
                        } else {
                            //// publish tap lines as test case steps

                            // construct test identifier

                            String id = fileName.replaceAll("\\.", "_");
                            if(!StringUtils.isBlank(tapMappingPrefix)) {
                                id = tapMappingPrefix + id;
                            }

                            log.fine(" TAP identifier parsed: " + id);

                            // if we already have a result parsed, peek it
                            TestCaseResult testCaseResult = null;
                            for(TestCaseResult tcr : results) {
                                if(id.equals(tcr.getMappingId())) {
                                    testCaseResult = tcr;
                                    break;
                                }
                            }

                            if(testCaseResult == null) {
                                testCaseResult = getTestCaseResult(build, id, testResult, "", "", user, r.getDuration());
                                results.add(testCaseResult);
                            }

                            TestCaseResultStep testCaseResultStep = new TestCaseResultStep();
                            testCaseResultStep.setResult(testResult);
                            testCaseResultStep.setDescription(tapTest);
                            testCaseResultStep.setComment(r.toString());
                            //testCaseResultStep.setExpected("");

                            List<TestCaseResultStep> steps = testCaseResult.getSteps();
                            if(steps == null) {
                                steps = new ArrayList<>();
                                testCaseResult.setSteps(steps);
                            }
                            steps.add(testCaseResultStep);

                            // we prefer to fail test cases if even one step is NOT OK
                            if(testResult == TestCaseResult.RESULT_FAIL) {
                                testCaseResult.setResult(TestCaseResult.RESULT_FAIL);
                            }

                            // construct test case result comment from step comments
                            String testCaseResultComment = testCaseResult.getComment();
                            if(testCaseResultComment.length() > 0)
                                testCaseResultComment += "\n";
                            testCaseResultComment += testCaseResultStep.getComment();
                            testCaseResult.setComment(testCaseResultComment);
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        log.warning("Could not parse TAP result row: " + r);
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

    protected static TestCaseResult getTestCaseResult(Run<?, ?> build, String id, int result, String msg, String stacktrace, String user, float duration) {
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

    public static boolean hasTAPSupport() {
        try {
            Class.forName("org.tap4j.plugin.model.TapStreamResult");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    /**
     * Reads Robot Framework output xml files from the system.
     */
    private static final class RobotOutputCallable extends MasterToSlaveFileCallable<String> {
        private String robotOutput;
        public RobotOutputCallable(String robotOutput) {
            this.robotOutput = robotOutput;
        }
        @Override
        public String invoke(File f, VirtualChannel channel) throws IOException, InterruptedException {
            FileSet fs = Util.createFileSet(f, robotOutput);
            DirectoryScanner ds = fs.getDirectoryScanner();
            String[] files = ds.getIncludedFiles();
            if(files.length > 0) {
                for(String file : files) {
                    if(log.isLoggable(Level.FINE))
                        log.fine("Matching robot output file found: " + ds.getBasedir().getAbsolutePath() + File.pathSeparator + file);
                }
                if(files.length > 1) {
                    throw new AbortException("Robot Output path " + robotOutput + " matches more than one file. Pattern must be more exact. Aborting.");
                }
                File outputXml = new File(ds.getBasedir(), files[0]);
                byte[] bytes = FileUtils.readFileToByteArray(outputXml);
                String encoding = detectXmlEncoding(bytes);
                if(encoding == null)
                    encoding = "UTF-8";
                return new String(bytes, encoding);
            }
            return null;
        }
    }

    /**
     * From XML file encoded as bytes, try to detect the XML encoding from the preamble.
     *
     * @param xml
     * @return
     */
    public static String detectXmlEncoding(byte[] xml) {
        try {
            if(xml == null)
                return null;
            XMLStreamReader r = XMLInputFactory.newInstance().createXMLStreamReader(new ByteArrayInputStream(xml));
            String encoding = r.getEncoding();
            r.close();
            return encoding;
        } catch (XMLStreamException xe) {
            return null;
        }
    }

}
