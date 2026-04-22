import org.junit.jupiter.api.*;
import org.mockito.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Test suite for Billing class SQL injection vulnerability remediation.
 *
 * This test suite validates that the SQL injection vulnerability in the
 * actionPerformed method has been properly fixed by using PreparedStatement
 * instead of string concatenation for SQL queries.
 */
public class BillingTest {

    private Billing billing;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;
    private ResultSet mockResultSet;

    @BeforeEach
    public void setUp() throws Exception {
        // Create mocks for database components
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockStatement = mock(Statement.class);
        mockResultSet = mock(ResultSet.class);

        // Create Billing instance
        billing = new Billing();

        // Use reflection to inject mock connection (since constructor creates real connection)
        java.lang.reflect.Field conField = Billing.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(billing, mockConnection);
    }

    /**
     * Test that PreparedStatement is used instead of Statement for INSERT query.
     * This verifies the SQL injection fix is in place.
     */
    @Test
    public void testUsesParameterizedQuery() throws Exception {
        // Setup mock behaviors
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Set up the GUI components with test data
        billing.Customer_Id.setText("CUST001");
        billing.Job_Id.setText("JOB001");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("10.5");
        billing.Net_Weight.setText("10.0");
        billing.Gross_Err.setText("0.1");
        billing.Weight_Err.setText("0.05");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Gold necklace");

        // Trigger the action
        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify PreparedStatement was created with parameterized query
        ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(queryCaptor.capture());

        String capturedQuery = queryCaptor.getValue();

        // Verify the query uses placeholders (?) instead of concatenated values
        assertTrue(capturedQuery.contains("?"),
            "Query should use parameterized placeholders");
        assertFalse(capturedQuery.contains("'CUST001'"),
            "Query should not contain concatenated customer ID");
        assertFalse(capturedQuery.contains("'10.5'"),
            "Query should not contain concatenated weight value");

        // Verify PreparedStatement methods were called with proper parameters
        verify(mockPreparedStatement).setString(eq(1), eq("CUST001"));
        verify(mockPreparedStatement).setString(eq(5), eq("10.5")); // Weight parameter
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempts in Weight field are safely handled.
     * The parameterized query should treat malicious input as literal data.
     */
    @Test
    public void testSqlInjectionInWeightFieldIsBlocked() throws Exception {
        // Setup mock behaviors
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Attempt SQL injection through Weight field
        String sqlInjectionAttempt = "10.5' OR '1'='1";

        billing.Customer_Id.setText("CUST001");
        billing.Job_Id.setText("JOB001");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText(sqlInjectionAttempt); // Malicious input
        billing.Net_Weight.setText("10.0");
        billing.Gross_Err.setText("0.1");
        billing.Weight_Err.setText("0.05");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Gold necklace");

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify the malicious input is passed as a parameter (safe)
        verify(mockPreparedStatement).setString(eq(5), eq(sqlInjectionAttempt));

        // Verify PreparedStatement was used (not Statement with concatenation)
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).executeUpdate();

        // Verify Statement.executeUpdate with concatenated query is NOT called
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test that SQL injection with DROP TABLE command is safely handled.
     */
    @Test
    public void testDropTableInjectionIsBlocked() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        String dropTableAttempt = "10'; DROP TABLE Billing; --";

        billing.Customer_Id.setText("CUST001");
        billing.Job_Id.setText("JOB001");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText(dropTableAttempt);
        billing.Net_Weight.setText("10.0");
        billing.Gross_Err.setText("0.1");
        billing.Weight_Err.setText("0.05");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify the DROP TABLE command is safely passed as a parameter value
        verify(mockPreparedStatement).setString(eq(5), eq(dropTableAttempt));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that multiple SQL injection attempts across different fields are blocked.
     */
    @Test
    public void testMultipleFieldsWithMaliciousInput() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Malicious input in multiple fields
        billing.Customer_Id.setText("CUST001' OR '1'='1");
        billing.Job_Id.setText("JOB001");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("10.5'; DELETE FROM Billing WHERE '1'='1");
        billing.Net_Weight.setText("10.0");
        billing.Gross_Err.setText("0.1");
        billing.Weight_Err.setText("0.05");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500' UNION SELECT * FROM Users --");
        billing.Details.setText("'; INSERT INTO Billing VALUES ('malicious'); --");

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify all malicious inputs are safely parameterized
        verify(mockPreparedStatement).setString(eq(1), contains("OR '1'='1"));
        verify(mockPreparedStatement).setString(eq(5), contains("DELETE FROM"));
        verify(mockPreparedStatement).setString(eq(12), contains("UNION SELECT"));
        verify(mockPreparedStatement).setString(eq(13), contains("INSERT INTO"));

        // Verify PreparedStatement is used (safe)
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that normal legitimate data still works correctly.
     */
    @Test
    public void testLegitimateDataProcessing() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Normal legitimate data
        billing.Customer_Id.setText("CUST001");
        billing.Job_Id.setText("JOB001");
        billing.Bill_Date.setText("15/03/2024");
        billing.Stone_Numbers.setText("8");
        billing.Weight.setText("25.75");
        billing.Net_Weight.setText("25.0");
        billing.Gross_Err.setText("0.2");
        billing.Weight_Err.setText("0.05");
        billing.Gold_Purity.setText("24K");
        billing.Total_Price.setText("125000");
        billing.Discount.setText("2500");
        billing.Details.setText("Gold ring with diamonds");

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify all parameters are set correctly
        verify(mockPreparedStatement).setString(1, "CUST001");
        verify(mockPreparedStatement).setString(2, "JOB001");
        verify(mockPreparedStatement).setString(3, "15/03/2024");
        verify(mockPreparedStatement).setString(4, "8");
        verify(mockPreparedStatement).setString(5, "25.75");
        verify(mockPreparedStatement).setString(6, "25.0");
        verify(mockPreparedStatement).setString(7, "0.2");
        verify(mockPreparedStatement).setString(8, "0.05");
        verify(mockPreparedStatement).setString(9, "24K");
        verify(mockPreparedStatement).setString(10, "125000");
        verify(mockPreparedStatement).setString(11, "Cash");
        verify(mockPreparedStatement).setString(12, "2500");
        verify(mockPreparedStatement).setString(13, "Gold ring with diamonds");

        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that special characters in weight field are properly escaped.
     */
    @Test
    public void testSpecialCharactersInWeight() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Special characters that could break SQL if not properly handled
        String specialCharsWeight = "10.5\"; SELECT * FROM Users; --";

        billing.Customer_Id.setText("CUST001");
        billing.Job_Id.setText("JOB001");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText(specialCharsWeight);
        billing.Net_Weight.setText("10.0");
        billing.Gross_Err.setText("0.1");
        billing.Weight_Err.setText("0.05");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify special characters are passed as literal values
        verify(mockPreparedStatement).setString(eq(5), eq(specialCharsWeight));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that empty or null weight values don't cause SQL injection.
     */
    @Test
    public void testEmptyWeightValue() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        billing.Customer_Id.setText("CUST001");
        billing.Job_Id.setText("JOB001");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText(""); // Empty weight
        billing.Net_Weight.setText("10.0");
        billing.Gross_Err.setText("0.1");
        billing.Weight_Err.setText("0.05");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify empty string is safely parameterized
        verify(mockPreparedStatement).setString(eq(5), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that the query structure matches expected parameterized format.
     */
    @Test
    public void testQueryStructureIsParameterized() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        billing.Customer_Id.setText("CUST001");
        billing.Job_Id.setText("JOB001");
        billing.Bill_Date.setText("01/01/2024");
        billing.Stone_Numbers.setText("5");
        billing.Weight.setText("10.5");
        billing.Net_Weight.setText("10.0");
        billing.Gross_Err.setText("0.1");
        billing.Weight_Err.setText("0.05");
        billing.Gold_Purity.setText("22K");
        billing.Total_Price.setText("50000");
        billing.Discount.setText("500");
        billing.Details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(queryCaptor.capture());

        String query = queryCaptor.getValue();

        // Count the number of ? placeholders (should be 13 for all fields)
        int placeholderCount = query.length() - query.replace("?", "").length();
        assertEquals(13, placeholderCount,
            "Query should have exactly 13 parameter placeholders");

        // Verify query doesn't contain concatenated string values
        assertFalse(query.contains("'+"),
            "Query should not contain string concatenation");
        assertFalse(query.contains("+'"),
            "Query should not contain string concatenation");
    }

    @AfterEach
    public void tearDown() {
        // Clean up
        billing = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockStatement = null;
        mockResultSet = null;
    }
}
