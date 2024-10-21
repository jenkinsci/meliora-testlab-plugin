package fi.meliora.testlab.ext.jenkins;

import fi.meliora.testlab.ext.rest.model.Changeset;
import hudson.*;
import hudson.model.*;
import hudson.scm.ChangeLogSet;
import hudson.tasks.*;
import hudson.util.ListBoxModel;
import hudson.util.PluginServletFilter;
import hudson.util.Secret;
import jenkins.scm.RunWithSCM;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import edu.umd.cs.findbugs.annotations.NonNull;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static fi.meliora.testlab.ext.rest.model.TestResult.*;

/**
 * A post build action to publish test results to Meliora Testlab.
 *
 * @author Meliora Ltd
 */
public class TestlabNotifier extends Notifier implements SimpleBuildStep {
    private final static Logger log = Logger.getLogger(TestlabNotifier.class.getName());

    /*
        BuildSteps that run after the build is completed.

        Notifier is a kind of Publisher that sends out the outcome of the builds
        to other systems and humans. This marking ensures that notifiers are run
        after the build result is set to its final value by other Recorders. To run
        even after the build is marked as complete, override Publisher.needsToRunAfterFinalized()
        to return true.

        This notifier can also be used as a Pipeline step:

        pipeline {
            agent any
            stages {
            ...
            }
            post {
                always {
                    junit '** /build/test-results/** /*.xml'
                    melioraTestlab(
                        projectKey: 'PRJX',
                        ruleset: 'ruleset to use for mapping',
                        automationSource: 'identifying source for the results'

                        rulesetSettings: [
                            testRunTitle: 'Automated tests',
                            milestone: 'M1',
                            testTargetTitle: 'Version 1.0',
                            testEnvironmentTitle: 'integration-env',

                            tags: 'jenkins nightly',

                            addIssueStrategy: 'DONOTADD' | 'ADDPERTESTRUN' | 'ADDPERTESTCASE' | 'ADDPERRESULT',
                            reopenExisting: true,
                            assignToUser: 'agentsmith',

                            robotCatenateParentKeywords: true
                        ],

                        description: 'Jenkins build: ${BUILD_FULL_DISPLAY_NAME} ${BUILD_RESULT}, ${BUILD_URL}',
                        parameters: 'BROWSER, USERNAME',

                        publishTap: [
                            tapTestsAsSteps: true,
                            tapFileNameInIdentifier: true,
                            tapTestNumberInIdentifier: false,
                            tapMappingPrefix: 'tap-'
                        ],

                        publishRobot: [
                            robotOutput: '** /output.xml'
                        ],

                        advancedSettings: [
                            companyId: 'testcompany',
                            apiKey: hudson.util.Secret.fromString('verysecretapikey'),
                            usingonpremise: [
                                onpremiseurl: 'http://testcompany:8080/'
                            ]
                        ]
                    )
                }
            }
        }
    */

    public static final String DEFAULT_DESCRIPTION_TEMPLATE
            = "Jenkins build: ${BUILD_FULL_DISPLAY_NAME} ${BUILD_RESULT}, ${BUILD_URL} - ${BUILD_STATUS}";

    public static final String DEFAULT_AUTOMATIONSOURCE = "${JOB_NAME}";

    /**
     * Note: All optional parameters need a setter annotated with @DataBoundSetter
     */

    // project key which to publish the results to
    private String projectKey;

    public String getProjectKey() {
        return projectKey;
    }

//    @DataBoundSetter
//    public void setProjectKey(String projectKey) {
//        this.projectKey = projectKey;
//    }

    // ruleset to use to map the results to test case
    private String ruleset;

    public String getRuleset() {
        return ruleset;
    }

    @DataBoundSetter
    public void setRuleset(String ruleset) {
        this.ruleset = ruleset;
    }

    // overridden ruleset settings
    private RulesetSettings rulesetSettings;

    public RulesetSettings getRulesetSettings() {
        return rulesetSettings;
    }

    @DataBoundSetter
    public void setRulesetSettings(RulesetSettings rulesetSettings) {
        this.rulesetSettings = rulesetSettings;
    }

    private String automationSource;

    public String getAutomationSource() {
        return automationSource;
    }

    @DataBoundSetter
    public void setAutomationSource(String automationSource) {
        this.automationSource = automationSource;
    }

    // description of the test run to create or update at Testlab side
    private String description;

    public String getDescription() {
        return description;
    }

    @DataBoundSetter
    public void setDescription(String description) {
        this.description = description;
    }

    // test case parameters to send from environmental variables
    private String parameters;

    public String getParameters() {
        return parameters;
    }

    @DataBoundSetter
    public void setParameters(String parameters) {
        this.parameters = parameters;
    }

    // If set, publish Robot Framework results
    private PublishRobot publishRobot;

    public PublishRobot getPublishRobot() {
        return publishRobot;
    }

    @DataBoundSetter
    public void setPublishRobot(PublishRobot publishRobot) {
        this.publishRobot = publishRobot;
    }

    // if set, publish TAP results
    private PublishTap publishTap;

    public PublishTap getPublishTap() {
        return publishTap;
    }

    @DataBoundSetter
    public void setPublishTap(PublishTap publishTap) {
        this.publishTap = publishTap;
    }

    // holder for optional advanced settings
    private AdvancedSettings advancedSettings;

    public AdvancedSettings getAdvancedSettings() {
        return advancedSettings;
    }

    @DataBoundSetter
    public void setAdvancedSettings(AdvancedSettings advancedSettings) {
        this.advancedSettings = advancedSettings;
    }

    /* pre-ruleset configuration, see readResolve */
    private transient String testRunTitle;
    private transient String milestone;
    private transient String testTargetTitle;
    private transient String testEnvironmentTitle;
    private transient IssuesSettings issuesSettings;
    private transient ImportTestCases importTestCases;
    private transient String tags;
    private transient String comment;
    /* /pre-ruleset configuration */

    protected Object readResolve() {
        //// migrate "pre-ruleset" configuration, if any
        //
        // if this plugin is run with old styled configuration, we pick these values here and
        //  persists them to a new ruleset-compatible model

        if(!isBlank(testRunTitle)) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();
            rulesetSettings.testRunTitle = testRunTitle;
            log.info("Migrated pre-ruleset configuration testRunTitle: " + testRunTitle);
            testRunTitle = null;
        }

        if(!isBlank(milestone)) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();
            rulesetSettings.milestone = milestone;
            log.info("Migrated pre-ruleset configuration milestone: " + milestone);
            milestone = null;
        }

        if(!isBlank(testTargetTitle)) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();
            rulesetSettings.testTargetTitle = testTargetTitle;
            log.info("Migrated pre-ruleset configuration testTargetTitle: " + testTargetTitle);
            testTargetTitle = null;
        }

        if(!isBlank(testEnvironmentTitle)) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();
            rulesetSettings.testEnvironmentTitle = testEnvironmentTitle;
            log.info("Migrated pre-ruleset configuration testEnvironmentTitle: " + testEnvironmentTitle);
            testEnvironmentTitle = null;
        }

        if(issuesSettings != null) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();
            if(issuesSettings.mergeAsSingleIssue)
                rulesetSettings.setAddIssueStrategy(AddIssueStrategy.ADDPERTESTCASE);
            else
                rulesetSettings.setAddIssueStrategy(AddIssueStrategy.ADDPERRESULT);

            rulesetSettings.assignToUser = issuesSettings.assignToUser;
            rulesetSettings.reopenExisting = issuesSettings.reopenExisting;
            log.info("Migrated pre-ruleset configuration issuesSettings: " + issuesSettings);
            issuesSettings = null;
        }

        if(importTestCases != null) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();
            rulesetSettings.importTestCases = true;
            rulesetSettings.importTestCasesRootCategory = importTestCases.importTestCasesRootCategory;
            log.info("Migrated pre-ruleset configuration importTestCases: " + importTestCases);
            importTestCases = null;
        }

        if(advancedSettings != null && !isBlank(advancedSettings.testCaseMappingField)) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();
            rulesetSettings.testCaseMappingField = advancedSettings.testCaseMappingField;
            log.info("Migrated pre-ruleset configuration advancedSettings.testCaseMappingField: " + advancedSettings.testCaseMappingField);
            advancedSettings.testCaseMappingField = null;
        }

        if(publishRobot != null && publishRobot.robotCatenateParentKeywords != null && !publishRobot.robotCatenateParentKeywords) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();
            rulesetSettings.robotCatenateParentKeywords = publishRobot.robotCatenateParentKeywords;
            log.info("Migrated pre-ruleset configuration publishRobot.robotCatenateParentKeywords: " + publishRobot.robotCatenateParentKeywords);
        }

        if(!isBlank(tags)) {
            if(rulesetSettings == null)
                rulesetSettings = new RulesetSettings();

            //used to use space separated tags, now comma separated
            String commaSeparatedTags = StringUtils.replace(tags, " ", ",");
            rulesetSettings.setTags(commaSeparatedTags);
        }

        if(!isBlank(comment)) {
            description = comment;
            log.info("Migrated pre-ruleset configuration comment to description as: " + description);
        }

        log.severe("Configuration resolved: " + this);

        return this;
    }

    /**
     * This annotation tells Hudson to call this constructor, with
     * values from the configuration form page with matching parameter names.
     */
    @DataBoundConstructor
    public TestlabNotifier(String projectKey, String ruleset, RulesetSettings rulesetSettings, String description, String parameters, PublishRobot publishRobot, PublishTap publishTap, AdvancedSettings advancedSettings) {
        super();
        this.projectKey = projectKey;
        this.ruleset = ruleset;
        this.rulesetSettings = rulesetSettings;
        this.description = description;
        this.parameters = parameters;
        this.publishRobot = publishRobot;
        this.publishTap = publishTap;
        this.advancedSettings = advancedSettings;
    }

    /**
     * Return true if this {@link hudson.tasks.Publisher} needs to run after the build result is
     * fully finalized.
     * <p/>
     * <p/>
     * The execution of normal {@link hudson.tasks.Publisher}s are considered within a part
     * of the build. This allows publishers to mark the build as a failure, or
     * to include their execution time in the total build time.
     * <p/>
     * <p/>
     * So normally, that is the preferrable behavior, but in a few cases
     * this is problematic. One of such cases is when a publisher needs to
     * trigger other builds, which in turn need to see this build as a
     * completed build. Those plugins that need to do this can return true
     * from this method, so that the {@link #perform(hudson.model.AbstractBuild, hudson.Launcher, hudson.model.BuildListener)}
     * method is called after the build is marked as completed.
     * <p/>
     * <p/>
     * When {@link hudson.tasks.Publisher} behaves this way, note that they can no longer
     * change the build status anymore.
     *
     * @since 1.153
     */
    @Override
    public boolean needsToRunAfterFinalized() {
        return true;
    }

    /**
     * Declares the scope of the synchronization monitor this {@link hudson.tasks.BuildStep} expects from outside.
     *
     * @since 1.319
     */
    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        // from the contract of SimpleBuildStep
        return BuildStepMonitor.NONE;
    }

    /**
     * SimpleBuildStep perform().
     *
     * @param run a build this is running as a part of
     * @param workspace a workspace to use for any file operations
     * @param launcher a way to start processes
     * @param listener a place to send output
     * @throws InterruptedException if the step is interrupted
     * @throws IOException if something goes wrong; use AbortException for a polite error
     */
    @Override
    public void perform(@NonNull Run<?, ?> run, @NonNull FilePath workspace, @NonNull Launcher launcher, @NonNull TaskListener listener) throws InterruptedException, IOException {
        doPerform(run, workspace, listener);
    }

    /**
     * Runs the step over the given build and reports the progress to the listener.
     *
     * A plugin can contribute the action object to Actionable.getActions() so that a 'report'
     * becomes a part of the persisted data of Build. This is how JUnit plugin attaches the
     * test report to a build page, for example.
     *
     * Using the return value to indicate success/failure should be considered deprecated,
     * and implementations are encouraged to throw AbortException to indicate a failure.
     *
     * @param build
     * @param launcher
     * @param listener
     * @return boolean deprecated
     * @throws InterruptedException
     * @throws IOException
     */
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
        return doPerform(build, build.getWorkspace(), listener);
    }

    /**
     * Execute our logic.
     *
     * Should throw AbortException for graceful and polite errors.
     */
    protected boolean doPerform(Run<?, ?> build, FilePath workspace, TaskListener listener) throws IOException, InterruptedException {
        listener.getLogger().println("Publishing test results to Testlab project: " + projectKey);

        DescriptorImpl d = getDescriptor();

        log.fine("perform(): " + this + ", descriptor: " + d);

        // get job specific settings if any and fallback to global configuration
        Secret secretKey = advancedSettings != null ? advancedSettings.apiKey : null;
        if(secretKey == null || "".equals(secretKey.getPlainText())) {
            // prefer key from global settings if the job has none
            secretKey = d.apiKey;
        }
        String runApiKey = secretKey != null ? secretKey.getPlainText() : null;

        Usingonpremise uop = advancedSettings != null && advancedSettings.usingonpremise != null
                ? advancedSettings.usingonpremise : d.usingonpremise;

        String runCompanyId = null, runOnpremiseurl = null;
        boolean runUsingonpremise = false;

        if(uop != null && !isBlank(uop.onpremiseurl)) {
            //
            // we apply onpremise settings only if they are complete
            //
            runCompanyId = null;
            runUsingonpremise = true;
            runOnpremiseurl = uop.onpremiseurl;

            log.fine("using on-premise with url: " + runOnpremiseurl);

        } else {
            //
            // otherwise we use companyId if present
            //
            runCompanyId = !isBlank(advancedSettings != null ? advancedSettings.companyId : null) ? advancedSettings.companyId : d.companyId;

            log.fine("using hosted with company id: " + runCompanyId);
        }

        // replace env vars for applicable fields

        EnvVars envVars = build.getEnvironment(listener);

        Map<String, String> additionalKeys = new HashMap<String, String>();
        additionalKeys.put("BUILD_FULL_DISPLAY_NAME", build.getFullDisplayName());
        Run.Summary summary = build.getBuildStatusSummary();
        additionalKeys.put("BUILD_STATUS", summary.message != null ? summary.message : "[No build status available]");
        Result result = build.getResult();
        additionalKeys.put("BUILD_RESULT", result != null ? result.toString() : "[No build result available]");

        VariableReplacer vr = new VariableReplacer(envVars, additionalKeys);

        if(log.isLoggable(Level.FINE)) {
            log.fine("Environment variables:");
            for(String key : vr.getVars().keySet()) {
                log.fine(" " + key + "=" + vr.getVars().get(key));
            }
        }

        String runProjectKey = vr.replace(projectKey);
        String runAutomationSource = vr.replace(isBlank(automationSource) ? DEFAULT_AUTOMATIONSOURCE : automationSource);
        String runMilestone = vr.replace(rulesetSettings != null ? rulesetSettings.milestone : null);
        String runTestRunTitle = vr.replace(rulesetSettings != null ? rulesetSettings.testRunTitle : null);
        String runDescription = vr.replace(isBlank(description) ? DEFAULT_DESCRIPTION_TEMPLATE : description);
        String runTestTargetTitle = vr.replace(rulesetSettings != null ? rulesetSettings.testTargetTitle : null);
        String runTestEnvironmentTitle = vr.replace(rulesetSettings != null ? rulesetSettings.testEnvironmentTitle : null);
        String runTags = vr.replace(rulesetSettings != null ? rulesetSettings.tags : null);
        String runAssignToUser = vr.replace(rulesetSettings != null ? rulesetSettings.assignToUser : null);
        String runRuleset = vr.replace(ruleset);
        String resultName = vr.replace("${BUILD_URL}");

        String runParameterVariables = vr.replace(parameters);
        Map<String, String> runParameters = null;
        if(runParameterVariables != null && runParameterVariables.trim().length() > 0) {
            String[] pars = runParameterVariables.split(",");
            Map<String, String> vars = vr.getVars();
            for(String par : pars) {
                par = par.trim();
                String value = vars.get(par);
                if(value == null)
                    value = vars.get(par.toUpperCase());
                if(value != null) {
                    if(runParameters == null)
                        runParameters = new HashMap<String, String>();
                    runParameters.put(par, value);
                }
            }
        }

        String runTapMappingPrefix = vr.replace(publishTap != null ? publishTap.tapMappingPrefix : null);       // nop on null

        String abortError = null;
        if(workspace == null) {
            abortError = "The provided build has no workspace.";
        }

        if(!runUsingonpremise && isBlank(runCompanyId)) {
            abortError = "Could not publish results to Testlab: Company ID is not set. Configure it for your job or globally in Jenkins' configuration.";
        }

        if(runUsingonpremise && isBlank(runOnpremiseurl)) {
            abortError = "Could not publish results to Testlab: Testlab URL for on-premise Testlab is not set. Configure it for your job or globally in Jenkins' configuration.";
        }

        if(isBlank(runApiKey)) {
            abortError = "Could not publish results to Testlab: Api Key is not set. Configure it for your job or globally in Jenkins' configuration.";
        }

        if(isBlank(runProjectKey)) {
            abortError = "Could not publish results to Testlab: Project key is not set. Configure it for your job or, if the value contains variable tags make sure they have values.";
        }

        if(abortError != null) {
            log.severe("Aborting with configuration: " + toString());
            listener.error(abortError);
            throw new AbortException(abortError);
        }

        // provide SCM information, if any
        List<String> culprits = null;
        List<Changeset> changesets = null;
        if(build instanceof RunWithSCM) {
            RunWithSCM<?, ?> runWithSCM = (RunWithSCM<?, ?>)build;
            List<ChangeLogSet<? extends ChangeLogSet.Entry>> jenkinsChangeSets = runWithSCM.getChangeSets();

            if(runWithSCM.shouldCalculateCulprits())
                runWithSCM.calculateCulprits();
            Set<String> culpritIds = runWithSCM.getCulpritIds();
            if(culpritIds != null)
                culprits = new ArrayList(culpritIds);

            log.fine("RunWithSCM, culprits: " + culpritIds + ", changesets: " + jenkinsChangeSets);

            if(jenkinsChangeSets.size() > 0) {
                for(ChangeLogSet<? extends ChangeLogSet.Entry> cls : jenkinsChangeSets) {
                    log.fine("Changeset: " + cls + ", Kind: " + cls.getKind());
                    if(cls.getItems() != null) {
                        if("git".equals(cls.getKind())) {
                            hudson.plugins.git.GitChangeSetList gcsl = (hudson.plugins.git.GitChangeSetList)cls;
                            List<hudson.plugins.git.GitChangeSet> sets = gcsl.getLogs();
                            if(sets != null) {
                                for(hudson.plugins.git.GitChangeSet set : sets) {
                                    String commitId = set.getCommitId();
                                    if(changesets == null)
                                        changesets = new ArrayList<Changeset>();
                                    Changeset cs = new Changeset();
                                    cs.setIdentifier(commitId);
                                    cs.setType(Changeset.TYPE_GIT);
                                    changesets.add(cs);
                                }
                            }
                        } else if("hg".equals(cls.getKind()) || "mercurial".equals(cls.getKind())) {
                            hudson.plugins.mercurial.MercurialChangeSetList mcsl = (hudson.plugins.mercurial.MercurialChangeSetList)cls;
                            List<hudson.plugins.mercurial.MercurialChangeSet> sets = mcsl.getLogs();
                            if(sets != null) {
                                for(hudson.plugins.mercurial.MercurialChangeSet set : sets) {
                                    String commitId = set.getCommitId();
                                    if(changesets == null)
                                        changesets = new ArrayList<Changeset>();
                                    Changeset cs = new Changeset();
                                    cs.setIdentifier(commitId);
                                    cs.setType(Changeset.TYPE_HG);
                                    changesets.add(cs);
                                }
                            }
                        }
                    }
                }
            }
            log.fine("RunWithSCM, sending changesets: " + changesets);
        }

        AddIssueStrategy addIssueStrategy = rulesetSettings != null ? rulesetSettings.addIssueStrategy : null;
        if(AddIssueStrategy.RULESET_DEFAULT.equals(addIssueStrategy))
            addIssueStrategy = null;

        Sender.sendResults(
                workspace,
                runCompanyId,
                runUsingonpremise,
                runOnpremiseurl,
                runApiKey,
                runProjectKey,
                runRuleset,
                runMilestone,
                runTestRunTitle,
                runDescription,
                runTestTargetTitle,
                runTestEnvironmentTitle,
                runTags,
                runParameters,
                addIssueStrategy,
                rulesetSettings != null ? rulesetSettings.reopenExisting : null,
                !isBlank(runAssignToUser) ? runAssignToUser : null,
                publishTap != null,
                publishTap != null && publishTap.tapTestsAsSteps,
                publishTap != null && publishTap.tapFileNameInIdentifier,
                publishTap != null && publishTap.tapTestNumberInIdentifier,
                runTapMappingPrefix,
                publishRobot != null,
                publishRobot != null ? publishRobot.robotOutput : null,
                rulesetSettings != null ? rulesetSettings.robotCatenateParentKeywords : null,
                runAutomationSource,
                resultName,
                culprits,
                changesets,
                build);

        return true;
    }


    @Override
    public DescriptorImpl getDescriptor() {
        // see Descriptor javadoc for more about what a descriptor is.
        return (DescriptorImpl)super.getDescriptor();
    }

    // this annotation tells Hudson that this is the implementation of an extension point
    @Extension
    @Symbol("melioraTestlab")
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {
        // company id of the testlab which to publish to
        public String companyId;
        // testlab api key
        public Secret apiKey;
        // if set, on-premise variant of Testlab is used and Testlab URL should be set and honored
        public Usingonpremise usingonpremise;
        // defines CORS settings for calls from Testlab -> Jenkins API
        public Cors cors;

        /* pre-ruleset configuration, see readResolve */
        // custom field name to map the test ids against with
        private transient String testCaseMappingField;
        /* /pre-ruleset configuration, see readResolve */

        private CORSFilter CORSFilter;

        public DescriptorImpl() {
            load();

            log.fine("load: " + companyId + ", api key hidden, " + usingonpremise + ", " + usingonpremise + ", " + cors);

            if(!isBlank(testCaseMappingField)) {
                log.warning(
                        "Meliora Testlab Plugin: In plugin settings, you have 'Test case mapping field' set" +
                        " as '" + testCaseMappingField + "'. This field is deprecated and should be set to each job's" +
                        " ruleset rules at Testlab side. See the plugin documentation on" +
                        " changes related to the introduction of ruleset-concept in Testlab. As deprecated, this value" +
                        " _will be ignored_."
                );
            }

            // let's inject our CORSFilter as we're at it
            try {
                CORSFilter = new CORSFilter();
                PluginServletFilter.addFilter(CORSFilter);
                log.info("CORSFilter injected.");
            } catch (ServletException se) {
                log.warning("Could not inject CORSFilter.");
                se.printStackTrace();
            }

            configureCORS();
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        @Override
        public String getDisplayName() {
            return "Publish test results to Testlab";
        }

        /**
         * Applicable to any kind of project.
         */
        @Override
        public boolean isApplicable(Class type) {
            return true;
        }

        @Override
        public boolean configure(StaplerRequest staplerRequest, JSONObject json) throws Descriptor.FormException {
            // persist configuration
            companyId = json.getString("companyId");
            apiKey = Secret.fromString(json.getString("apiKey"));

            JSONObject uop = json.getJSONObject("usingonpremise");
            if(uop != null && !uop.isNullObject() && !uop.isEmpty()) {
                usingonpremise = new Usingonpremise(uop.getString("onpremiseurl"));
            } else {
                usingonpremise = null;
            }

            JSONObject c = json.getJSONObject("cors");
            if(c != null && !c.isNullObject() && !c.isEmpty()) {
                cors = new Cors(c.getString("origin"));
            } else {
                cors = null;
            }

            log.fine("configure: " + companyId + ", api key hidden, " + usingonpremise + ", " + cors);

            save();

            configureCORS();

            return true; // indicate that everything is good so far
        }

        protected void configureCORS() {
            CORSFilter.setEnabled(cors != null && !isBlank(cors.origin));
            if(cors != null && cors.origin != null) {
                //
                // parse a comma separated list to a list of allowed origins
                //
                String[] spl = cors.origin.split(",");
                List<String> origins = new ArrayList<String>();
                for(String o : spl) {
                    origins.add(o.trim());
                }
                CORSFilter.setOrigins(origins);
            }
        }

        public String getDefaultDescriptionTemplate() {
            return DEFAULT_DESCRIPTION_TEMPLATE;
        }

        public String getDefaultAutomationSource() {
            return DEFAULT_AUTOMATIONSOURCE;
        }

        @SuppressWarnings("unused")
        @Restricted(NoExternalUse.class)
        public ListBoxModel doFillAddIssuesItems() {
            return getRulesetDefaultBooleanModel();
        }

        @SuppressWarnings("unused")
        @Restricted(NoExternalUse.class)
        public ListBoxModel doFillMergeAsSingleIssueItems() {
            return getRulesetDefaultBooleanModel();
        }

        @SuppressWarnings("unused")
        @Restricted(NoExternalUse.class)
        public ListBoxModel doFillReopenExistingItems() {
            return getRulesetDefaultBooleanModel();
        }

        @SuppressWarnings("unused")
        @Restricted(NoExternalUse.class)
        public ListBoxModel doFillImportTestCasesItems() {
            return getRulesetDefaultBooleanModel();
        }

        @SuppressWarnings("unused")
        @Restricted(NoExternalUse.class)
        public ListBoxModel doFillRobotCatenateParentKeywordsItems() {
            return getRulesetDefaultBooleanModel();
        }

        @SuppressWarnings("unused")
        @Restricted(NoExternalUse.class)
        public ListBoxModel doFillAddIssueStrategyItems() {
            ListBoxModel m = new ListBoxModel();
            m.add("[Ruleset default]", AddIssueStrategy.RULESET_DEFAULT.toString());
            m.add("Do not add issues", AddIssueStrategy.DONOTADD.toString());
            m.add("Add an issue per test run", AddIssueStrategy.ADDPERTESTRUN.toString());
            m.add("Add an issue per Testlab test case", AddIssueStrategy.ADDPERTESTCASE.toString());
            m.add("Add an issue per test result", AddIssueStrategy.ADDPERRESULT.toString());
            return m;
        }

        protected ListBoxModel getRulesetDefaultBooleanModel() {
            ListBoxModel m = new ListBoxModel();
            m.add("[Ruleset default]", "null");
            m.add("Yes", "true");
            m.add("No", "false");
            return m;
        }

        @Override
        public String toString() {
            return "DescriptorImpl{" +
                    "companyId='" + companyId + '\'' +
                    ", apiKey='hidden'" +
                    ", usingonpremise=" + usingonpremise +
                    ", cors=" + cors +
                    '}';
        }
    }

    /**
     * Optional job config block for ruleset settings.
     *
     * If set implicitly implies that some ruleset settings should be overridden.
     */
    public static final class RulesetSettings {
        // name of the test run to create or update at Testlab side
        private String testRunTitle;

        public String getTestRunTitle() {
            return testRunTitle;
        }

        @DataBoundSetter
        public void setTestRunTitle(String testRunTitle) {
            this.testRunTitle = testRunTitle;
        }

        // identifier or a title of a milestone the results are bound to in Testlab
        private String milestone;

        public String getMilestone() {
            return milestone;
        }

        @DataBoundSetter
        public void setMilestone(String milestone) {
            this.milestone = milestone;
        }

        // title of the version the results are bound to in Testlab
        private String testTargetTitle;

        public String getTestTargetTitle() {
            return testTargetTitle;
        }

        @DataBoundSetter
        public void setTestTargetTitle(String testTargetTitle) {
            this.testTargetTitle = testTargetTitle;
        }

        // title of the environment the results are bound to in Testlab
        private String testEnvironmentTitle;

        public String getTestEnvironmentTitle() {
            return testEnvironmentTitle;
        }

        @DataBoundSetter
        public void setTestEnvironmentTitle(String testEnvironmentTitle) {
            this.testEnvironmentTitle = testEnvironmentTitle;
        }

        private AddIssueStrategy addIssueStrategy;
        public AddIssueStrategy getAddIssueStrategy() {
            return addIssueStrategy;
        }
        @DataBoundSetter
        public void setAddIssueStrategy(AddIssueStrategy addIssueStrategy) {
            this.addIssueStrategy = addIssueStrategy;
        }

        // if set issues are automatically assigned to this user
        private String assignToUser;

        public String getAssignToUser() {
            return assignToUser;
        }

        @DataBoundSetter
        public void setAssignToUser(String assignToUser) {
            this.assignToUser = assignToUser;
        }

        // if set we try to reopen existing matching issues on push
        private Boolean reopenExisting;

        @DataBoundSetter
        public void setReopenExisting(Boolean reopenExisting) {
            this.reopenExisting = reopenExisting;
        }

        public Boolean getReopenExisting() {
            return reopenExisting;
        }

        // if true we try to automatically create test cases for tests
        private Boolean importTestCases;

        @DataBoundSetter
        public void setImportTestCases(Boolean importTestCases) {
            this.importTestCases = importTestCases;
        }

        public Boolean getImportTestCases() {
            return importTestCases;
        }

        private String tags;
        public String getTags() {
            return tags;
        }
        @DataBoundSetter
        public void setTags(String tags) {
            this.tags = tags;
        }

        // test category where the automatically created test cases will be created to. Defaults to 'Import'.
        @Deprecated
        private String importTestCasesRootCategory;

        @Deprecated
        @DataBoundSetter
        public void setImportTestCasesRootCategory(String importTestCasesRootCategory) {
            this.importTestCasesRootCategory = importTestCasesRootCategory;
        }

        @Deprecated
        public String getImportTestCasesRootCategory() {
            return importTestCasesRootCategory;
        }

        // if set, all keywords and their sub keywords are catenated to a single step in the result when possible
        private Boolean robotCatenateParentKeywords;

        @DataBoundSetter
        public void setRobotCatenateParentKeywords(Boolean robotCatenateParentKeywords) {
            this.robotCatenateParentKeywords = robotCatenateParentKeywords;
        }

        public Boolean getRobotCatenateParentKeywords() {
            return robotCatenateParentKeywords;
        }

        // testlab field to use to store the mapping ID's of automated tests when automatically creating test cases
        @Deprecated
        private String testCaseMappingField;

        @Deprecated
        @DataBoundSetter
        public void setTestCaseMappingField(String testCaseMappingField) {
            this.testCaseMappingField = testCaseMappingField;
        }

        @Deprecated
        public String getTestCaseMappingField() {
            return testCaseMappingField;
        }

        public RulesetSettings() {}

        @DataBoundConstructor
        public RulesetSettings(String testRunTitle, String milestone, String testTargetTitle, String testEnvironmentTitle, AddIssueStrategy addIssueStrategy, Boolean reopenExisting, String assignToUser, Boolean importTestCases, String importTestCasesRootCategory, Boolean robotCatenateParentKeywords, String testCaseMappingField) {
            this.testRunTitle = testRunTitle;
            this.milestone = milestone;
            this.testTargetTitle = testTargetTitle;
            this.testEnvironmentTitle = testEnvironmentTitle;
            this.addIssueStrategy = addIssueStrategy;
            this.reopenExisting = reopenExisting;
            this.assignToUser = assignToUser;
            this.importTestCases = importTestCases;
            this.importTestCasesRootCategory = importTestCasesRootCategory;
            this.robotCatenateParentKeywords = robotCatenateParentKeywords;
            this.testCaseMappingField = testCaseMappingField;
        }

        @Override
        public String toString() {
            return "RulesetSettings{" +
                    "testRunTitle='" + testRunTitle + '\'' +
                    ", milestone='" + milestone + '\'' +
                    ", testTargetTitle='" + testTargetTitle + '\'' +
                    ", testEnvironmentTitle='" + testEnvironmentTitle + '\'' +
                    ", addIssueStrategy=" + addIssueStrategy +
                    ", reopenExisting=" + reopenExisting +
                    ", assignToUser='" + assignToUser + '\'' +
                    ", robotCatenateParentKeywords=" + robotCatenateParentKeywords +
                    '}';
        }
    }

    /**
     * Optional job config block for advanced settings.
     */
    public static final class AdvancedSettings {
        // job specific company ID of target testlab, optional
        private String companyId;

        public String getCompanyId() {
            return companyId;
        }

        @DataBoundSetter
        public void setCompanyId(String companyId) {
            this.companyId = companyId;
        }

        // if set, on-premise variant of Testlab is used and Testlab URL should be set and honored
        private Usingonpremise usingonpremise;

        public Usingonpremise getUsingonpremise() {
            return usingonpremise;
        }

        @DataBoundSetter
        public void setUsingonpremise(Usingonpremise usingonpremise) {
            this.usingonpremise = usingonpremise;
        }

        // job specific apikey of target testlab, optional
        private Secret apiKey;

        public Secret getApiKey() {
            return apiKey;
        }

        @DataBoundSetter
        public void setApiKey(Secret apiKey) {
            this.apiKey = apiKey;
        }

        /* pre-ruleset configuration, see readResolve */
        // title of the Testlab custom field to use to map the unit tests to Testlab's test cases, optional
        public transient String testCaseMappingField;
        /* /pre-ruleset configuration, see readResolve */

        @DataBoundConstructor
        public AdvancedSettings(String companyId, Secret apiKey, String testCaseMappingField, Usingonpremise usingonpremise) {
            this.companyId = companyId;
            this.apiKey = apiKey;
            this.usingonpremise = usingonpremise;
            this.testCaseMappingField = testCaseMappingField;
        }

        @Override
        public String toString() {
            return "AdvancedSettings{" +
                    "companyId='" + companyId + '\'' +
                    ", usingonpremise=" + usingonpremise +
                    ", apiKey='hidden'" +
                    '}';
        }
    }

    /**
     * Optional job config block for on-premise settings.
     */
    public static final class Usingonpremise {
        // full url address of on-premise Testlab
        private String onpremiseurl;

        public String getOnpremiseurl() {
            return onpremiseurl;
        }

        @DataBoundSetter
        public void setOnpremiseurl(String onpremiseurl) {
            this.onpremiseurl = onpremiseurl;
        }

        @DataBoundConstructor
        public Usingonpremise(String onpremiseurl) {
            this.onpremiseurl = onpremiseurl;
        }

        @Override
        public String toString() {
            return "Usingonpremise{" +
                    "onpremiseurl='" + onpremiseurl + '\'' +
                    '}';
        }
    }

    /**
     * Optional job config block for issues.
     *
     * If set implicitly implies that issues should be added on push.
     */
    public static final class IssuesSettings {
        /* pre-ruleset configuration, see readResolve */
        // if true added issues are merged and added as a single issue
        public boolean mergeAsSingleIssue;
        // if set issues are automatically assigned to this user
        public String assignToUser;
        // if set we try to reopen existing matching issues on push
        public boolean reopenExisting;
        /* /pre-ruleset configuration, see readResolve */

        @DataBoundConstructor
        public IssuesSettings(boolean mergeAsSingleIssue, String assignToUser, boolean reopenExisting) {
            this.mergeAsSingleIssue = mergeAsSingleIssue;
            this.assignToUser = assignToUser;
            this.reopenExisting = reopenExisting;
        }

        @Override
        public String toString() {
            return "IssuesSettings{" +
                    "mergeAsSingleIssue(pre)=" + mergeAsSingleIssue +
                    ", assignToUser(pre)='" + assignToUser + '\'' +
                    ", reopenExisting(pre)=" + reopenExisting +
                    '}';
        }
    }

    /**
     * Optional config block for CORS settings.
     */
    public static final class Cors {
        // allow origin
        private String origin;

        public String getOrigin() {
            return origin;
        }

        @DataBoundSetter
        public void setOrigin(String origin) {
            this.origin = origin;
        }

        @DataBoundConstructor
        public Cors(String origin) {
            this.origin = origin;
        }

        @Override
        public String toString() {
            return "Cors{" +
                    "origin='" + origin + '\'' +
                    '}';
        }
    }

    /**
     * Optional job config block for TAP support.
     *
     * If set implicitly implies that TAP results should be published to Testlab.
     */
    public static final class PublishTap {
        // If set, each TAP file will be mapped to a single test case in Testlab and the steps of the test case will be overwritten and matched to sent lines in TAP file
        private boolean tapTestsAsSteps;

        public boolean isTapTestsAsSteps() {
            return tapTestsAsSteps;
        }

        @DataBoundSetter
        public void setTapTestsAsSteps(boolean tapTestsAsSteps) {
            this.tapTestsAsSteps = tapTestsAsSteps;
        }

        // If set, the name of the TAP file containing the tests is included in the mapping identifier as a prefix
        private boolean tapFileNameInIdentifier;

        public boolean isTapFileNameInIdentifier() {
            return tapFileNameInIdentifier;
        }

        @DataBoundSetter
        public void setTapFileNameInIdentifier(boolean tapFileNameInIdentifier) {
            this.tapFileNameInIdentifier = tapFileNameInIdentifier;
        }

        // If set, the mapping identifier will not include the test number of the TAP test
        private boolean tapTestNumberInIdentifier;

        public boolean isTapTestNumberInIdentifier() {
            return tapTestNumberInIdentifier;
        }

        @DataBoundSetter
        public void setTapTestNumberInIdentifier(boolean tapTestNumberInIdentifier) {
            this.tapTestNumberInIdentifier = tapTestNumberInIdentifier;
        }

        // If set, mapping identifiers sent will be prefixed with this value
        private String tapMappingPrefix;

        public String getTapMappingPrefix() {
            return tapMappingPrefix;
        }

        @DataBoundSetter
        public void setTapMappingPrefix(String tapMappingPrefix) {
            this.tapMappingPrefix = tapMappingPrefix;
        }

        @DataBoundConstructor
        public PublishTap(boolean tapFileNameInIdentifier, boolean tapTestNumberInIdentifier, boolean tapTestsAsSteps, String tapMappingPrefix) {
            this.tapFileNameInIdentifier = tapFileNameInIdentifier;
            this.tapTestNumberInIdentifier = tapTestNumberInIdentifier;
            this.tapTestsAsSteps = tapTestsAsSteps;
            this.tapMappingPrefix = tapMappingPrefix;
        }

        @Override
        public String toString() {
            return "PublishTap{" +
                    "tapFileNameInIdentifier=" + tapFileNameInIdentifier +
                    ", tapTestsAsSteps=" + tapTestsAsSteps +
                    ", tapTestNumberInIdentifier=" + tapTestNumberInIdentifier +
                    ", tapMappingPrefix=" + tapMappingPrefix +
                    '}';
        }
    }

    /**
     * Optional job config block for Robot Framework support.
     *
     * If set implicitly implies that Robot results should be published to Testlab.
     */
    public static final class PublishRobot {
        // Robot output.xml file path
        private String robotOutput;

        public String getRobotOutput() {
            return robotOutput;
        }

        @DataBoundSetter
        public void setRobotOutput(String robotOutput) {
            this.robotOutput = robotOutput;
        }

        /* pre-ruleset configuration, see readResolve */
        // If set, catenates all sub keywords of a keyword as a single step in result
        public transient Boolean robotCatenateParentKeywords = true;
        /* /pre-ruleset configuration, see readResolve */

        @DataBoundConstructor
        public PublishRobot(String robotOutput, Boolean robotCatenateParentKeywords) {
            this.robotOutput = robotOutput;
            this.robotCatenateParentKeywords = robotCatenateParentKeywords == null ? true : robotCatenateParentKeywords;
        }

        @Override
        public String toString() {
            return "PublishRobot{" +
                    "robotOutput='" + robotOutput + '\'' +
                    "robotCatenateParentKeywords(pre)=" + robotCatenateParentKeywords +
                    '}';
        }
    }

    /**
     * Optional job config block for auto-creating test cases.
     *
     * If set implicitly implies that test cases should be automatically created during the push.
     */
    @Deprecated
    public static final class ImportTestCases {
        /* pre-ruleset configuration, see readResolve */
        // If set, sets the root category path where the test cases are created. By default, "Import".
        public String importTestCasesRootCategory;
        /* /pre-ruleset configuration, see readResolve */

        @DataBoundConstructor
        public ImportTestCases(String importTestCasesRootCategory) {
            this.importTestCasesRootCategory = importTestCasesRootCategory;
        }

        @Override
        public String toString() {
            return "ImportTestCases{" +
                    "importTestCasesRootCategory(pre)='" + importTestCasesRootCategory + '\'' +
                    '}';
        }
    }

    /**
     * @return true if trimmed String is empty
     */
    public static boolean isBlank(String s) {
        return s == null || s.trim().length() == 0;
    }

    @Override
    public String toString() {
        return "TestlabNotifier{" +
                "projectKey='" + projectKey + '\'' +
                ", ruleset='" + ruleset + '\'' +
                ", rulesetSettings=" + rulesetSettings +
                ", description='" + description + '\'' +
                ", tags='" + tags + '\'' +
                ", parameters='" + parameters + '\'' +
                ", publishRobot=" + publishRobot +
                ", publishTap=" + publishTap +
                ", advancedSettings=" + advancedSettings +
                ", testRunTitle(pre)='" + testRunTitle + '\'' +
                ", milestone(pre)='" + milestone + '\'' +
                ", testTargetTitle(pre)='" + testTargetTitle + '\'' +
                ", testEnvironmentTitle(pre)='" + testEnvironmentTitle + '\'' +
                ", issuesSettings(pre)=" + issuesSettings +
                ", descriptor=" + getDescriptor() +
                "}";
    }

}
