import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Test suite for Billing class to verify SQL injection vulnerability remediation.
 *
 * This test suite specifically validates that the billing insertion functionality
 * is protected against SQL injection attacks by using PreparedStatements with
 * parameterized queries instead of string concatenation.
 */
public class BillingTest {

    private Billing billing;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;
    private ResultSet mockResultSet;

    @BeforeEach
    public void setUp() throws Exception {
        // Create mock database objects
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockStatement = mock(Statement.class);
        mockResultSet = mock(ResultSet.class);

        // Setup the Billing instance with mocked connection
        billing = new Billing();

        // Use reflection to inject the mock connection
        java.lang.reflect.Field conField = Billing.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(billing, mockConnection);
    }

    @AfterEach
    public void tearDown() {
        billing = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockStatement = null;
        mockResultSet = null;
    }

    /**
     * Test that the billing insert uses PreparedStatement instead of Statement.
     * This is the primary defense against SQL injection.
     */
    @Test
    public void testBillingInsertUsesPreparedStatement() throws Exception {
        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Setup the billing frame
        JDesktopPane desktop = new JDesktopPane();
        billing.BillingFrame(desktop);

        // Set form values with normal data
        billing.Customer_Id.setText("123");
        billing.Job_Id.setText("456");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("100.5");
        billing.Net_Weight.setText("95.3");
        billing.Gross_Err.setText("0.5");
        billing.Weight_Err.setText("0.2");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test billing");

        // Trigger the action
        ActionEvent event = new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "Submit");
        billing.actionPerformed(event);

        // Verify that prepareStatement was called (indicating parameterized query usage)
        verify(mockConnection).prepareStatement(contains("INSERT INTO Billing"));
        verify(mockConnection).prepareStatement(contains("?"));

        // Verify that executeUpdate was called on the PreparedStatement
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempts in Customer_Id are safely handled.
     * The parameterized query should treat malicious input as literal data.
     */
    @Test
    public void testSqlInjectionInCustomerId() throws Exception {
        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Setup the billing frame
        JDesktopPane desktop = new JDesktopPane();
        billing.BillingFrame(desktop);

        // Set form values with SQL injection attempt in Customer_Id
        billing.Customer_Id.setText("1' OR '1'='1");
        billing.Job_Id.setText("456");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("100.5");
        billing.Net_Weight.setText("95.3");
        billing.Gross_Err.setText("0.5");
        billing.Weight_Err.setText("0.2");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test billing");

        // Trigger the action
        ActionEvent event = new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "Submit");
        billing.actionPerformed(event);

        // Verify that setString was called with the malicious input as a literal string
        verify(mockPreparedStatement).setString(eq(1), eq("1' OR '1'='1"));

        // Verify that the PreparedStatement was used (not vulnerable Statement)
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempts in Bill_Date are safely handled.
     */
    @Test
    public void testSqlInjectionInBillDate() throws Exception {
        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Setup the billing frame
        JDesktopPane desktop = new JDesktopPane();
        billing.BillingFrame(desktop);

        // Set form values with SQL injection attempt in Bill_Date
        billing.Customer_Id.setText("123");
        billing.Job_Id.setText("456");
        billing.Bill_Date.setText("01/01/2024'); DROP TABLE Billing; --");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("100.5");
        billing.Net_Weight.setText("95.3");
        billing.Gross_Err.setText("0.5");
        billing.Weight_Err.setText("0.2");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test billing");

        // Trigger the action
        ActionEvent event = new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "Submit");
        billing.actionPerformed(event);

        // Verify that setString was called with the malicious input as a literal string
        verify(mockPreparedStatement).setString(eq(3), eq("01/01/2024'); DROP TABLE Billing; --"));

        // Verify that the PreparedStatement was used
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection with UNION SELECT is safely handled.
     */
    @Test
    public void testSqlInjectionUnionSelect() throws Exception {
        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Setup the billing frame
        JDesktopPane desktop = new JDesktopPane();
        billing.BillingFrame(desktop);

        // Set form values with UNION SELECT injection attempt
        billing.Customer_Id.setText("123");
        billing.Job_Id.setText("456");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("100.5");
        billing.Net_Weight.setText("95.3");
        billing.Gross_Err.setText("0.5");
        billing.Weight_Err.setText("0.2");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("') UNION SELECT * FROM users WHERE ('1'='1");

        // Trigger the action
        ActionEvent event = new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "Submit");
        billing.actionPerformed(event);

        // Verify that setString was called with the malicious input as a literal string
        verify(mockPreparedStatement).setString(eq(13), eq("') UNION SELECT * FROM users WHERE ('1'='1"));

        // Verify that the PreparedStatement was used
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that multiple special SQL characters are safely handled.
     */
    @Test
    public void testSqlInjectionSpecialCharacters() throws Exception {
        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Setup the billing frame
        JDesktopPane desktop = new JDesktopPane();
        billing.BillingFrame(desktop);

        // Set form values with various special SQL characters
        billing.Customer_Id.setText("'; -- /* */ ");
        billing.Job_Id.setText("456");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("100.5");
        billing.Net_Weight.setText("95.3");
        billing.Gross_Err.setText("0.5");
        billing.Weight_Err.setText("0.2");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test with 'quotes' and \"double quotes\"");

        // Trigger the action
        ActionEvent event = new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "Submit");
        billing.actionPerformed(event);

        // Verify that special characters were passed safely as parameters
        verify(mockPreparedStatement).setString(eq(1), contains("';"));
        verify(mockPreparedStatement).setString(eq(13), contains("quotes"));

        // Verify that the PreparedStatement was used
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test normal billing operation with legitimate data.
     * This ensures the fix doesn't break existing functionality.
     */
    @Test
    public void testNormalBillingOperation() throws Exception {
        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Setup the billing frame
        JDesktopPane desktop = new JDesktopPane();
        billing.BillingFrame(desktop);

        // Set form values with normal, legitimate data
        billing.Customer_Id.setText("C123");
        billing.Job_Id.setText("J456");
        billing.Bill_Date.setText("15/03/2024");
        billing.Stone_Numbers.setText("10");
        billing.Weight.setText("250.75");
        billing.Net_Weight.setText("240.50");
        billing.Gross_Err.setText("1.25");
        billing.Weight_Err.setText("0.75");
        billing.Gold_Purity.setText("24K");
        billing.Total_Price.setText("125000.00");
        billing.Discount.setText("2500.00");
        billing.Details.setText("Gold necklace with diamond stones");

        // Trigger the action
        ActionEvent event = new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "Submit");
        billing.actionPerformed(event);

        // Verify all parameters were set correctly
        verify(mockPreparedStatement).setString(1, "C123");
        verify(mockPreparedStatement).setString(2, "J456");
        verify(mockPreparedStatement).setString(3, "15/03/2024");
        verify(mockPreparedStatement).setString(4, "10");
        verify(mockPreparedStatement).setString(5, "250.75");
        verify(mockPreparedStatement).setString(6, "240.50");
        verify(mockPreparedStatement).setString(7, "1.25");
        verify(mockPreparedStatement).setString(8, "0.75");
        verify(mockPreparedStatement).setString(9, "24K");
        verify(mockPreparedStatement).setString(10, "125000.00");
        verify(mockPreparedStatement).setString(11, "Cash");
        verify(mockPreparedStatement).setString(12, "2500.00");
        verify(mockPreparedStatement).setString(13, "Gold necklace with diamond stones");

        // Verify that executeUpdate was called
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that all 13 parameters are properly bound to the PreparedStatement.
     * This ensures no parameters are missed in the remediation.
     */
    @Test
    public void testAllParametersAreBound() throws Exception {
        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Setup the billing frame
        JDesktopPane desktop = new JDesktopPane();
        billing.BillingFrame(desktop);

        // Set all form values
        billing.Customer_Id.setText("C1");
        billing.Job_Id.setText("J1");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("1");
        billing.Weight.setText("10");
        billing.Net_Weight.setText("9");
        billing.Gross_Err.setText("0.1");
        billing.Weight_Err.setText("0.1");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("1000");
        billing.Discount.setText("100");
        billing.Details.setText("Test");

        // Trigger the action
        ActionEvent event = new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "Submit");
        billing.actionPerformed(event);

        // Verify that all 13 parameters were set
        verify(mockPreparedStatement, times(1)).setString(eq(1), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(2), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(3), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(4), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(5), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(6), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(7), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(8), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(9), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(10), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(11), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(12), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(13), anyString());
    }

    /**
     * Test that SQL injection with time-based payloads are safely handled.
     */
    @Test
    public void testSqlInjectionTimeBasedPayload() throws Exception {
        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Setup the billing frame
        JDesktopPane desktop = new JDesktopPane();
        billing.BillingFrame(desktop);

        // Set form values with time-based SQL injection payload
        billing.Customer_Id.setText("1'; WAITFOR DELAY '00:00:05'--");
        billing.Job_Id.setText("456");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("100.5");
        billing.Net_Weight.setText("95.3");
        billing.Gross_Err.setText("0.5");
        billing.Weight_Err.setText("0.2");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test");

        // Trigger the action
        ActionEvent event = new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "Submit");
        billing.actionPerformed(event);

        // Verify that the time-based payload was treated as literal data
        verify(mockPreparedStatement).setString(eq(1), eq("1'; WAITFOR DELAY '00:00:05'--"));

        // Verify that the PreparedStatement was used
        verify(mockPreparedStatement).executeUpdate();
    }
}
