package fi.meliora.testlab.ext.rest.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 * Encapsulates inbound results of a single test run.
 *
 * @author Marko Kanala
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TestResult extends ModelObject {
    public static final int STATUS_NOTSTARTED = 0;
    public static final int STATUS_STARTED = 1;
    public static final int STATUS_ABORTED = 2;
    public static final int STATUS_FINISHED = 3;

    @XmlElement
    private Long projectId;
    @XmlElement
    private String projectKey;

    @XmlElement
    private Long testRunId;
    @XmlElement
    private String testRunTitle;

    @XmlElement
    private String comment;

    @XmlElement
    private int status;

    @XmlElement
    private String user;

    @XmlElement
    private Long milestoneId;
    @XmlElement
    private String milestoneIdentifier;
    @XmlElement
    private String milestoneTitle;

    @XmlElement
    private Long testTargetId;
    @XmlElement
    private String testTargetTitle;

    @XmlElement
    private Long testEnvironmentId;
    @XmlElement
    private String testEnvironmentTitle;

    @XmlElement
    private String tags;

    @XmlElement(type = KeyValuePair.class)
    private List<KeyValuePair> parameters;

    @XmlElement(type = TestCaseResult.class)
    private List<TestCaseResult> results;

    // control fields

    @XmlElement
    private String testCaseMappingField;

    @XmlElement
    private boolean addIssues;
    @XmlElement
    private boolean mergeAsSingleIssue;
    @XmlElement
    private boolean reopenExistingIssues;
    @XmlElement
    private String assignIssuesToUser;

    public Long getProjectId() {
        return projectId;
    }

    /**
     * Id of the project to add the test results to. If null, projectKey is used.
     *
     * @param projectId
     */
    public void setProjectId(Long projectId) {
        this.projectId = projectId;
    }

    public String getProjectKey() {
        return projectKey;
    }

    /**
     * Key of the project to add the test results to. Optional if projectId is set.
     *
     * @param projectKey
     */
    public void setProjectKey(String projectKey) {
        this.projectKey = projectKey;
    }

    public Long getTestRunId() {
        return testRunId;
    }

    /**
     * Id of the test run to update the test results to. If null, testRunTitle is used.
     *
     * @param testRunId
     */
    public void setTestRunId(Long testRunId) {
        this.testRunId = testRunId;
    }

    public String getTestRunTitle() {
        return testRunTitle;
    }

    /**
     * Title of the test run to update the test results to. Optional if testRunId is set.
     *
     * @param testRunTitle
     */
    public void setTestRunTitle(String testRunTitle) {
        this.testRunTitle = testRunTitle;
    }

    public String getComment() {
        return comment;
    }

    /**
     * Comment for the test run. If test run exists and comment is left as null the comment
     * of TestRun at Testlab is left as it is.
     *
     * @param comment
     */
    public void setComment(String comment) {
        this.comment = comment;
    }

    public int getStatus() {
        return status;
    }

    /**
     * Status for test run.
     *
     * @param status
     */
    public void setStatus(int status) {
        this.status = status;
    }

    public String getUser() {
        return user;
    }

    /**
     * Name of the user to execute Testlab operations with.
     *
     * @param user
     */
    public void setUser(String user) {
        this.user = user;
    }

    public Long getMilestoneId() {
        return milestoneId;
    }

    /**
     * Id of the milestone for the test run and issues. If null, milestoneIdentifier and milestoneTitle are used.
     *
     * @param milestoneId
     */
    public void setMilestoneId(Long milestoneId) {
        this.milestoneId = milestoneId;
    }

    public String getMilestoneIdentifier() {
        return milestoneIdentifier;
    }

    /**
     * Identifier of the milestone for the test run and issues. If null, milestoneTitle is used.
     *
     * @param milestoneIdentifier
     */
    public void setMilestoneIdentifier(String milestoneIdentifier) {
        this.milestoneIdentifier = milestoneIdentifier;
    }

    public String getMilestoneTitle() {
        return milestoneTitle;
    }

    /**
     * Title of the milestone for the test run and issues.
     *
     * @param milestoneTitle
     */
    public void setMilestoneTitle(String milestoneTitle) {
        this.milestoneTitle = milestoneTitle;
    }

    public Long getTestTargetId() {
        return testTargetId;
    }

    /**
     * Id of the test target (version) for the test run. If null, testTargetTitle is used.
     *
     * @param testTargetId
     */
    public void setTestTargetId(Long testTargetId) {
        this.testTargetId = testTargetId;
    }

    public String getTestTargetTitle() {
        return testTargetTitle;
    }

    /**
     * Title of the test target (version) for the test run. Optional if testTargetId is set.
     *
     * @param testTargetTitle
     */
    public void setTestTargetTitle(String testTargetTitle) {
        this.testTargetTitle = testTargetTitle;
    }

    public Long getTestEnvironmentId() {
        return testEnvironmentId;
    }

    /**
     * Id of the test environment for the test run. If null, testEnvironmentTitle is used.
     *
     * @param testEnvironmentId
     */
    public void setTestEnvironmentId(Long testEnvironmentId) {
        this.testEnvironmentId = testEnvironmentId;
    }

    public String getTestEnvironmentTitle() {
        return testEnvironmentTitle;
    }

    /**
     * Title of the test environment for the test run. Optional if testEnvironmentId is set.
     *
     * @param testEnvironmentTitle
     */
    public void setTestEnvironmentTitle(String testEnvironmentTitle) {
        this.testEnvironmentTitle = testEnvironmentTitle;
    }

    public String getTags() {
        return tags;
    }

    /**
     * Tags for the test run. Optional. Separate multiple tags with spaces ("tag1 tag2 tag3 ...").
     *
     * @param tags
     */
    public void setTags(String tags) {
        this.tags = tags;
    }

    public String getTestCaseMappingField() {
        return testCaseMappingField;
    }

    /**
     * Title of the custom field to use to map the test cases from the project. Optional
     * if results are sent with actual testCaseId values set.
     *
     * This value is case-insensitive.
     *
     * @param testCaseMappingField
     */
    public void setTestCaseMappingField(String testCaseMappingField) {
        this.testCaseMappingField = testCaseMappingField;
    }

    public List<TestCaseResult> getResults() {
        return results;
    }

    /**
     * Values to set to test case parameters if any.
     *
     * @return
     */
    public List<KeyValuePair> getParameters() {
        return parameters;
    }

    public void setParameters(List<KeyValuePair> parameters) {
        this.parameters = parameters;
    }

    /**
     * Results of individual test cases.
     *
     * @param results
     */
    public void setResults(List<TestCaseResult> results) {
        this.results = results;
    }

    public boolean isAddIssues() {
        return addIssues;
    }

    /**
     * Set to true to add issues for failed test cases.
     *
     * @param addIssues
     */
    public void setAddIssues(boolean addIssues) {
        this.addIssues = addIssues;
    }

    public boolean isMergeAsSingleIssue() {
        return mergeAsSingleIssue;
    }

    /**
     * Set to true to merge added issues to a single issue.
     *
     * @param mergeAsSingleIssue
     */
    public void setMergeAsSingleIssue(boolean mergeAsSingleIssue) {
        this.mergeAsSingleIssue = mergeAsSingleIssue;
    }

    public boolean isReopenExistingIssues() {
        return reopenExistingIssues;
    }

    /**
     * Set to true to reopen existing issues in Testlab if found.
     *
     * @param reopenExistingIssues
     */
    public void setReopenExistingIssues(boolean reopenExistingIssues) {
        this.reopenExistingIssues = reopenExistingIssues;
    }

    public String getAssignIssuesToUser() {
        return assignIssuesToUser;
    }

    /**
     * Assign added issues to this user if the user is found in the project.
     *
     * @param assignIssuesToUser
     */
    public void setAssignIssuesToUser(String assignIssuesToUser) {
        this.assignIssuesToUser = assignIssuesToUser;
    }
}
