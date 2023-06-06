package fi.meliora.testlab.ext.jenkins.test;

import org.htmlunit.html.*;
import fi.meliora.testlab.ext.jenkins.TestlabNotifier;
import hudson.model.FreeStyleProject;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * Jenkins tests for testing meliora testlab plugin's settings.
 *
 * @author Meliora Ltd
 */
public class SettingsTest extends TestBase {

    /**
     * <ul>
     *     <li>Loads up the /configure page</li>
     *     <li>asserts that we have our configuration fields available and they are empty</li>
     *     <li>sets some values and saves the configuration</li>
     *     <li>loads up the /configure page</li>
     *     <li>asserts that the values have been saved</li>
     * </ul>
     *
     * @throws Exception
     */
    @Test
    public void testGlobalSettings() throws Exception {
        JenkinsRule.WebClient client = getWebClient();
        client.login("admin", "admin");

        HtmlPage configureSystemPage = client.goTo("configure");
        HtmlForm form = configureSystemPage.getFormByName("config");

        HtmlTextInput companyIdInput = form.getInputByName(FIELD_COMPANYID);
        HtmlCheckBoxInput usingonpremiseInput = form.getInputByName(FIELD_USINGONPREMISE);
        HtmlTextInput onpremiseurlInput = form.getInputByName(FIELD_ONPREMISEURL);
        HtmlTextInput apiKeyInput = form.getInputByName(FIELD_APIKEY);
        HtmlCheckBoxInput corsInput = form.getInputByName(FIELD_CORS);
        HtmlTextInput originsInput = form.getInputByName(FIELD_ORIGIN);

        assertEmpty(companyIdInput);
        assertChecked(usingonpremiseInput, false);
        assertEmpty(onpremiseurlInput);
        assertEmpty(apiKeyInput);
        assertChecked(corsInput, false);
        assertHasValue(originsInput, "*");

        companyIdInput.setValue("unittestcompany");
        usingonpremiseInput.setChecked(true);
        onpremiseurlInput.setValue("https://unittesthost:8080");
        apiKeyInput.setValue("1010101010202020");
        corsInput.setChecked(true);
        originsInput.setValue("http://somehost, http://anotherhost");

        j.submit(form);

        configureSystemPage = client.goTo("configure");
        form = configureSystemPage.getFormByName("config");

        companyIdInput = form.getInputByName(FIELD_COMPANYID);
        usingonpremiseInput = form.getInputByName(FIELD_USINGONPREMISE);
        onpremiseurlInput = form.getInputByName(FIELD_ONPREMISEURL);
        HtmlHiddenInput hiddenApiKeyInput = form.getInputByName(FIELD_APIKEY);
        corsInput = form.getInputByName(FIELD_CORS);
        originsInput = form.getInputByName(FIELD_ORIGIN);

        assertHasValue(companyIdInput, "unittestcompany");
        assertChecked(usingonpremiseInput, true);
        assertHasValue(onpremiseurlInput, "https://unittesthost:8080");
        assertPassword(hiddenApiKeyInput, "1010101010202020");
        assertChecked(corsInput, true);
        assertHasValue(originsInput, "http://somehost, http://anotherhost");
    }

    /**
     * <ul>
     *     <li>adds a new free style project</li>
     *     <li>adds our plugin to the project as post-build action</li>
     *     <li>loads up the job configuration page</li>
     *     <li>asserts that we have our configuration fields available for the job and they are empty</li>
     *     <li>sets only required fields</li>
     *     <li>loads up the job configuration page</li>
     *     <li>asserts that the values have been saved</li>
     *     <li>sets add issues block fields</li>
     *     <li>loads up the job configuration page</li>
     *     <li>asserts that the values have been saved</li>
     *     <li>sets advanced settings block fields</li>
     *     <li>loads up the job configuration page</li>
     *     <li>asserts that the values have been saved</li>
     * </ul>
     *
     * @throws Exception
     */
    @Test
    public void testJobSettings() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject("test");
        p.getPublishersList().add(new TestlabNotifier(null, null, null, null, null, null, null, null));

        JenkinsRule.WebClient client = getWebClient();
        client.login("admin", "admin");

        HtmlPage configurePage = client.goTo("job/test/configure");

        HtmlForm form = configurePage.getFormByName("config");

        HtmlTextInput projectkeyInput = form.getInputByName(FIELD_PROJECTKEY);
        HtmlTextInput rulesetInput = form.getInputByName(FIELD_RULESET);
        HtmlTextInput automationSourceInput = form.getInputByName(FIELD_AUTOMATIONSOURCE);

        HtmlCheckBoxInput rulesetSettingsInput = form.getInputByName(FIELD_BLOCK_RULESETSETTINGS);
        HtmlTextInput testRunTitleInput = form.getInputByName(FIELD_TESTRUNTITLE);
        HtmlTextInput milestoneInput = form.getInputByName(FIELD_MILESTONE);
        HtmlTextInput testTargetTitleInput = form.getInputByName(FIELD_TESTTARGETTITLE);
        HtmlTextInput testEnvironmentTitleInput = form.getInputByName(FIELD_TESTENVIRONMENTTITLE);
        HtmlSelect addIssueStrategyInput = form.getSelectByName(FIELD_ADDISSUESTRATEGY);
        HtmlSelect reopenExistingInput = form.getSelectByName(FIELD_REOPENEXISTING);
        HtmlTextInput assignToUserInput = form.getInputByName(FIELD_ASSIGNTOUSER);
        HtmlSelect robotCatenateParentKeywordsInput = form.getSelectByName(FIELD_ROBOTCATENATEPARENTKEYWORDS);

        HtmlCheckBoxInput advancedSettingsInput = form.getInputByName(FIELD_BLOCK_ADVANCEDSETTINGS);
        HtmlTextInput companyIdInput = form.getInputByName(FIELD_COMPANYID);
        HtmlCheckBoxInput usingonpremiseInput = form.getInputByName(FIELD_USINGONPREMISE);
        HtmlTextInput onpremiseurlInput = form.getInputByName(FIELD_ONPREMISEURL);
        HtmlTextInput apiKeyInput = form.getInputByName(FIELD_APIKEY);

        HtmlTextArea commentInput = form.getTextAreaByName(FIELD_DESCRIPTION);
        HtmlTextInput tagsInput = form.getInputByName(FIELD_TAGS);
        HtmlTextInput parametersInput = form.getInputByName(FIELD_PARAMETERS);

        HtmlCheckBoxInput publishTapInput = form.getInputByName(FIELD_BLOCK_PUBLISHTAP);
        HtmlCheckBoxInput tapTestsAsStepsInput = form.getInputByName(FIELD_TAPTESTSASSTEPS);
        HtmlCheckBoxInput tapFileNameInIdentifier = form.getInputByName(FIELD_TAPFILENAMEINIDENTIFIER);
        HtmlCheckBoxInput tapTestNumberInIdentifier = form.getInputByName(FIELD_TAPTESTNUMBERINIDENTIFIER);
        HtmlTextInput tapMappingPrefixInput = form.getInputByName(FIELD_TAPMAPPINGPREFIX);
        HtmlCheckBoxInput publishRobotInput = form.getInputByName(FIELD_BLOCK_PUBLISHROBOT);
        HtmlTextInput robotOutputInput = form.getInputByName(FIELD_ROBOTOUTPUT);

        assertEmpty(projectkeyInput);
        assertEmpty(rulesetInput);
        assertHasValue(automationSourceInput, TestlabNotifier.DEFAULT_AUTOMATIONSOURCE);

        assertChecked(rulesetSettingsInput, false);
        assertEmpty(testRunTitleInput);
        assertEmpty(milestoneInput);
        assertEmpty(testTargetTitleInput);
        assertEmpty(testEnvironmentTitleInput);
        assertSingleSelected(addIssueStrategyInput, "RULESET_DEFAULT");
        assertSingleSelected(reopenExistingInput, "null");
        assertEmpty(assignToUserInput);
        assertSingleSelected(robotCatenateParentKeywordsInput, "null");

        assertChecked(advancedSettingsInput, false);
        assertEmpty(companyIdInput);
        assertChecked(usingonpremiseInput, false);
        assertEmpty(onpremiseurlInput);
        assertEmpty(apiKeyInput);

        assertHasValue(commentInput, TestlabNotifier.DEFAULT_DESCRIPTION_TEMPLATE);
        assertEmpty(tagsInput);

        assertEmpty(parametersInput);

        assertChecked(publishTapInput, false);
        assertChecked(tapTestsAsStepsInput, false);
        assertChecked(tapFileNameInIdentifier, true);       // defaults to true
        assertChecked(tapTestNumberInIdentifier, false);
        assertEmpty(tapMappingPrefixInput);

        assertChecked(publishRobotInput, false);
        assertHasValue(robotOutputInput, "**/output.xml");

        //// set only required fields and assert save

        projectkeyInput.setValue("PROJ");
        rulesetInput.setValue("ruleset");
        automationSourceInput.setValue("source");
        j.submit(form);
        configurePage = client.goTo("job/test/configure");
        form = configurePage.getFormByName("config");

        projectkeyInput = form.getInputByName(FIELD_PROJECTKEY);
        automationSourceInput = form.getInputByName(FIELD_AUTOMATIONSOURCE);
        rulesetInput = form.getInputByName(FIELD_RULESET);
        rulesetSettingsInput = form.getInputByName(FIELD_BLOCK_RULESETSETTINGS);
        testRunTitleInput = form.getInputByName(FIELD_TESTRUNTITLE);
        milestoneInput = form.getInputByName(FIELD_MILESTONE);
        testTargetTitleInput = form.getInputByName(FIELD_TESTTARGETTITLE);
        testEnvironmentTitleInput = form.getInputByName(FIELD_TESTENVIRONMENTTITLE);
        addIssueStrategyInput = form.getSelectByName(FIELD_ADDISSUESTRATEGY);
        reopenExistingInput = form.getSelectByName(FIELD_REOPENEXISTING);
        assignToUserInput = form.getInputByName(FIELD_ASSIGNTOUSER);
        robotCatenateParentKeywordsInput = form.getSelectByName(FIELD_ROBOTCATENATEPARENTKEYWORDS);
        advancedSettingsInput = form.getInputByName(FIELD_BLOCK_ADVANCEDSETTINGS);
        companyIdInput = form.getInputByName(FIELD_COMPANYID);
        usingonpremiseInput = form.getInputByName(FIELD_USINGONPREMISE);
        onpremiseurlInput = form.getInputByName(FIELD_ONPREMISEURL);
        apiKeyInput = form.getInputByName(FIELD_APIKEY);
        commentInput = form.getTextAreaByName(FIELD_DESCRIPTION);
        tagsInput = form.getInputByName(FIELD_TAGS);
        parametersInput = form.getInputByName(FIELD_PARAMETERS);
        publishTapInput = form.getInputByName(FIELD_BLOCK_PUBLISHTAP);
        tapTestsAsStepsInput = form.getInputByName(FIELD_TAPTESTSASSTEPS);
        tapFileNameInIdentifier = form.getInputByName(FIELD_TAPFILENAMEINIDENTIFIER);
        tapTestNumberInIdentifier = form.getInputByName(FIELD_TAPTESTNUMBERINIDENTIFIER);
        tapMappingPrefixInput = form.getInputByName(FIELD_TAPMAPPINGPREFIX);
        publishRobotInput = form.getInputByName(FIELD_BLOCK_PUBLISHROBOT);
        robotOutputInput = form.getInputByName(FIELD_ROBOTOUTPUT);

        assertHasValue(projectkeyInput, "PROJ");
        assertHasValue(automationSourceInput, "source");
        assertHasValue(rulesetInput, "ruleset");
        assertChecked(rulesetSettingsInput, false);
        assertEmpty(testRunTitleInput);
        assertEmpty(milestoneInput);
        assertEmpty(testTargetTitleInput);
        assertEmpty(testEnvironmentTitleInput);
        assertSingleSelected(addIssueStrategyInput, "RULESET_DEFAULT");
        assertSingleSelected(reopenExistingInput, "null");
        assertEmpty(assignToUserInput);
        assertSingleSelected(robotCatenateParentKeywordsInput, "null");
        assertChecked(advancedSettingsInput, false);
        assertEmpty(companyIdInput);
        assertChecked(usingonpremiseInput, false);
        assertEmpty(onpremiseurlInput);
        assertEmpty(apiKeyInput);
        assertHasValue(commentInput, TestlabNotifier.DEFAULT_DESCRIPTION_TEMPLATE);
        assertEmpty(tagsInput);
        assertEmpty(parametersInput);
        assertChecked(publishTapInput, false);
        assertChecked(tapTestsAsStepsInput, false);
        assertChecked(tapFileNameInIdentifier, true);       // defaults to true
        assertChecked(tapTestNumberInIdentifier, false);
        assertEmpty(tapMappingPrefixInput);
        assertChecked(publishRobotInput, false);
        assertHasValue(robotOutputInput, "**/output.xml");

        //// set other optional fields and issues block and assert save

        rulesetSettingsInput.setChecked(true);
        testRunTitleInput.setValue("Test run");
        milestoneInput.setValue("Milestone 1");
        testTargetTitleInput.setValue("Some version");
        testEnvironmentTitleInput.setValue("Some env");
        addIssueStrategyInput.setSelectedAttribute("ADDPERTESTRUN", true);
        reopenExistingInput.setSelectedAttribute("true", true);
        assignToUserInput.setValue("someuser");
        commentInput.setText("comment text");
        tagsInput.setValue("jenkins tags");
        parametersInput.setValue("var1, var2");
        publishTapInput.setChecked(true);
        tapTestsAsStepsInput.setChecked(true);
        tapFileNameInIdentifier.setChecked(false);
        tapTestNumberInIdentifier.setChecked(true);
        tapMappingPrefixInput.setValue("PREF");
        publishRobotInput.setChecked(true);
        robotOutputInput.setValue("results/output2.xml");
        robotCatenateParentKeywordsInput.setSelectedAttribute("false", true);

        j.submit(form);
        configurePage = client.goTo("job/test/configure");

        l("AFTER SUBMIT");
        l(configurePage.asXml());

        form = configurePage.getFormByName("config");

        projectkeyInput = form.getInputByName(FIELD_PROJECTKEY);
        automationSourceInput = form.getInputByName(FIELD_AUTOMATIONSOURCE);
        rulesetInput = form.getInputByName(FIELD_RULESET);
        rulesetSettingsInput = form.getInputByName(FIELD_BLOCK_RULESETSETTINGS);
        testRunTitleInput = form.getInputByName(FIELD_TESTRUNTITLE);
        milestoneInput = form.getInputByName(FIELD_MILESTONE);
        testTargetTitleInput = form.getInputByName(FIELD_TESTTARGETTITLE);
        testEnvironmentTitleInput = form.getInputByName(FIELD_TESTENVIRONMENTTITLE);
        addIssueStrategyInput = form.getSelectByName(FIELD_ADDISSUESTRATEGY);
        reopenExistingInput = form.getSelectByName(FIELD_REOPENEXISTING);
        assignToUserInput = form.getInputByName(FIELD_ASSIGNTOUSER);
        robotCatenateParentKeywordsInput = form.getSelectByName(FIELD_ROBOTCATENATEPARENTKEYWORDS);
        advancedSettingsInput = form.getInputByName(FIELD_BLOCK_ADVANCEDSETTINGS);
        companyIdInput = form.getInputByName(FIELD_COMPANYID);
        usingonpremiseInput = form.getInputByName(FIELD_USINGONPREMISE);
        onpremiseurlInput = form.getInputByName(FIELD_ONPREMISEURL);
        apiKeyInput = form.getInputByName(FIELD_APIKEY);
        commentInput = form.getTextAreaByName(FIELD_DESCRIPTION);
        tagsInput = form.getInputByName(FIELD_TAGS);
        parametersInput = form.getInputByName(FIELD_PARAMETERS);
        publishTapInput = form.getInputByName(FIELD_BLOCK_PUBLISHTAP);
        tapTestsAsStepsInput = form.getInputByName(FIELD_TAPTESTSASSTEPS);
        tapFileNameInIdentifier = form.getInputByName(FIELD_TAPFILENAMEINIDENTIFIER);
        tapTestNumberInIdentifier = form.getInputByName(FIELD_TAPTESTNUMBERINIDENTIFIER);
        tapMappingPrefixInput = form.getInputByName(FIELD_TAPMAPPINGPREFIX);
        publishRobotInput = form.getInputByName(FIELD_BLOCK_PUBLISHROBOT);
        robotOutputInput = form.getInputByName(FIELD_ROBOTOUTPUT);

        assertHasValue(projectkeyInput, "PROJ");
        assertHasValue(rulesetInput, "ruleset");
        assertHasValue(automationSourceInput,"source");

        assertChecked(rulesetSettingsInput, true);
        assertHasValue(testRunTitleInput, "Test run");
        assertHasValue(milestoneInput, "Milestone 1");
        assertHasValue(testTargetTitleInput, "Some version");
        assertHasValue(testEnvironmentTitleInput, "Some env");

        assertSingleSelected(addIssueStrategyInput, "ADDPERTESTRUN");
        assertSingleSelected(reopenExistingInput, "true");
        assertHasValue(assignToUserInput, "someuser");

        assertChecked(advancedSettingsInput, false);
        assertEmpty(companyIdInput);
        assertEmpty(apiKeyInput);

        assertHasValue(commentInput, "comment text");
        assertHasValue(tagsInput, "jenkins tags");

        assertHasValue(parametersInput, "var1, var2");

        assertChecked(publishTapInput, true);
        assertChecked(tapTestsAsStepsInput, true);
        assertChecked(tapFileNameInIdentifier, false);
        assertChecked(tapTestNumberInIdentifier, true);
        assertHasValue(tapMappingPrefixInput, "PREF");

        assertChecked(publishRobotInput, true);
        assertHasValue(robotOutputInput, "results/output2.xml");
        assertSingleSelected(robotCatenateParentKeywordsInput, "false");

        //// set advanced setting fields and assert save

        advancedSettingsInput.setChecked(true);
        companyIdInput.setValue("unittestcompanyjob");
        usingonpremiseInput.setChecked(true);
        onpremiseurlInput.setValue("https://unittesthost:8080");
        apiKeyInput.setValue("1010101010303030");
        j.submit(form);
        configurePage = client.goTo("job/test/configure");
        form = configurePage.getFormByName("config");

        projectkeyInput = form.getInputByName(FIELD_PROJECTKEY);
        automationSourceInput = form.getInputByName(FIELD_AUTOMATIONSOURCE);
        rulesetInput = form.getInputByName(FIELD_RULESET);
        rulesetSettingsInput = form.getInputByName(FIELD_BLOCK_RULESETSETTINGS);
        testRunTitleInput = form.getInputByName(FIELD_TESTRUNTITLE);
        milestoneInput = form.getInputByName(FIELD_MILESTONE);
        testTargetTitleInput = form.getInputByName(FIELD_TESTTARGETTITLE);
        testEnvironmentTitleInput = form.getInputByName(FIELD_TESTENVIRONMENTTITLE);
        addIssueStrategyInput = form.getSelectByName(FIELD_ADDISSUESTRATEGY);
        reopenExistingInput = form.getSelectByName(FIELD_REOPENEXISTING);
        assignToUserInput = form.getInputByName(FIELD_ASSIGNTOUSER);
        robotCatenateParentKeywordsInput = form.getSelectByName(FIELD_ROBOTCATENATEPARENTKEYWORDS);
        advancedSettingsInput = form.getInputByName(FIELD_BLOCK_ADVANCEDSETTINGS);
        companyIdInput = form.getInputByName(FIELD_COMPANYID);
        usingonpremiseInput = form.getInputByName(FIELD_USINGONPREMISE);
        onpremiseurlInput = form.getInputByName(FIELD_ONPREMISEURL);
        HtmlHiddenInput hiddenApiKeyInput = form.getInputByName(FIELD_APIKEY);
        commentInput = form.getTextAreaByName(FIELD_DESCRIPTION);
        tagsInput = form.getInputByName(FIELD_TAGS);
        parametersInput = form.getInputByName(FIELD_PARAMETERS);
        publishTapInput = form.getInputByName(FIELD_BLOCK_PUBLISHTAP);
        tapTestsAsStepsInput = form.getInputByName(FIELD_TAPTESTSASSTEPS);
        tapFileNameInIdentifier = form.getInputByName(FIELD_TAPFILENAMEINIDENTIFIER);
        tapTestNumberInIdentifier = form.getInputByName(FIELD_TAPTESTNUMBERINIDENTIFIER);
        tapMappingPrefixInput = form.getInputByName(FIELD_TAPMAPPINGPREFIX);
        publishRobotInput = form.getInputByName(FIELD_BLOCK_PUBLISHROBOT);
        robotOutputInput = form.getInputByName(FIELD_ROBOTOUTPUT);

        assertHasValue(projectkeyInput, "PROJ");
        assertHasValue(rulesetInput, "ruleset");
        assertHasValue(automationSourceInput, "source");

        assertChecked(rulesetSettingsInput, true);
        assertHasValue(testRunTitleInput, "Test run");
        assertHasValue(milestoneInput, "Milestone 1");
        assertHasValue(testTargetTitleInput, "Some version");
        assertHasValue(testEnvironmentTitleInput, "Some env");

        assertSingleSelected(addIssueStrategyInput, "ADDPERTESTRUN");
        assertSingleSelected(reopenExistingInput, "true");
        assertHasValue(assignToUserInput, "someuser");

        assertHasValue(commentInput, "comment text");
        assertHasValue(tagsInput, "jenkins tags");

        assertHasValue(parametersInput, "var1, var2");

        assertChecked(publishTapInput, true);
        assertChecked(tapTestsAsStepsInput, true);
        assertChecked(tapFileNameInIdentifier, false);
        assertChecked(tapTestNumberInIdentifier, true);
        assertHasValue(tapMappingPrefixInput, "PREF");

        assertChecked(publishRobotInput, true);
        assertHasValue(robotOutputInput, "results/output2.xml");
        assertSingleSelected(robotCatenateParentKeywordsInput, "false");

        assertChecked(advancedSettingsInput, true);
        assertHasValue(companyIdInput, "unittestcompanyjob");
        assertChecked(usingonpremiseInput, true);
        assertHasValue(onpremiseurlInput, "https://unittesthost:8080");
        assertPassword(hiddenApiKeyInput, "1010101010303030");
    }

}
