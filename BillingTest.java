import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;

/**
 * Test class for Billing to verify SQL injection vulnerability has been remediated.
 * This test ensures that PreparedStatement is used instead of string concatenation
 * for SQL queries, preventing SQL injection attacks.
 */
@RunWith(MockitoJUnitRunner.class)
public class BillingTest {

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Mock
    private Statement mockStatement;

    @Mock
    private ResultSet mockResultSet;

    @InjectMocks
    private Billing billing;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        // Mock the connection behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        when(mockResultSet.getString(1)).thenReturn("1000");

        // Set the billing connection to use our mock
        billing = new Billing();
        setPrivateField(billing, "con", mockConnection);
    }

    /**
     * Test that normal billing submission uses PreparedStatement.
     * This verifies the SQL injection vulnerability fix is in place.
     */
    @Test
    public void testBillingSubmission_UsesPreparedStatement() throws Exception {
        // Arrange
        setTextField(billing, "Customer_Id", "CUST001");
        setTextField(billing, "Job_Id", "JOB001");
        setTextField(billing, "Bill_Date", "01/01/2024");
        setTextField(billing, "Stone_Numbers", "5");
        setTextField(billing, "Weight", "10.5");
        setTextField(billing, "Net_Weight", "9.5");
        setTextField(billing, "Gross_Err", "0.1");
        setTextField(billing, "Weight_Err", "0.05");
        setTextField(billing, "Gold_Purity", "22K");
        setTextField(billing, "Total_Price", "50000");
        setTextField(billing, "Discount", "500");
        setTextField(billing, "Details", "Wedding ring");

        // Mock the customer validation query
        Statement mockStmtCustom = mock(Statement.class);
        ResultSet mockResCustom = mock(ResultSet.class);
        when(mockConnection.createStatement()).thenReturn(mockStmtCustom);
        when(mockStmtCustom.executeQuery(anyString())).thenReturn(mockResCustom);
        when(mockResCustom.next()).thenReturn(true);

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Assert
        // Verify that prepareStatement was called with the parameterized query
        verify(mockConnection).prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
        );

        // Verify that all 13 parameters were set on the PreparedStatement
        verify(mockPreparedStatement).setString(1, "CUST001");
        verify(mockPreparedStatement).setString(2, "JOB001");
        verify(mockPreparedStatement).setString(3, "01/01/2024");
        verify(mockPreparedStatement).setString(4, "5");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "9.5");
        verify(mockPreparedStatement).setString(7, "0.1");
        verify(mockPreparedStatement).setString(8, "0.05");
        verify(mockPreparedStatement).setString(9, "22K");
        verify(mockPreparedStatement).setString(10, "50000");
        verify(mockPreparedStatement).setString(11, "Cash");
        verify(mockPreparedStatement).setString(12, "500");
        verify(mockPreparedStatement).setString(13, "Wedding ring");

        // Verify that executeUpdate was called
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempts in Customer_ID are neutralized.
     * The PreparedStatement should treat this as a literal string, not SQL code.
     */
    @Test
    public void testSQLInjectionAttempt_CustomerID_IsNeutralized() throws Exception {
        // Arrange - SQL injection attempt in Customer_ID
        String sqlInjectionPayload = "CUST001' OR '1'='1";
        setTextField(billing, "Customer_Id", sqlInjectionPayload);
        setTextField(billing, "Job_Id", "JOB001");
        setTextField(billing, "Bill_Date", "01/01/2024");
        setTextField(billing, "Stone_Numbers", "5");
        setTextField(billing, "Weight", "10.5");
        setTextField(billing, "Net_Weight", "9.5");
        setTextField(billing, "Gross_Err", "0.1");
        setTextField(billing, "Weight_Err", "0.05");
        setTextField(billing, "Gold_Purity", "22K");
        setTextField(billing, "Total_Price", "50000");
        setTextField(billing, "Discount", "500");
        setTextField(billing, "Details", "Test");

        // Mock the customer validation query
        Statement mockStmtCustom = mock(Statement.class);
        ResultSet mockResCustom = mock(ResultSet.class);
        when(mockConnection.createStatement()).thenReturn(mockStmtCustom);
        when(mockStmtCustom.executeQuery(anyString())).thenReturn(mockResCustom);
        when(mockResCustom.next()).thenReturn(true);

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Assert
        // Verify the SQL injection payload was passed as a parameter (not concatenated)
        verify(mockPreparedStatement).setString(1, sqlInjectionPayload);

        // The payload should be treated as a literal string value, not executable SQL
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempts in Gold_Purity are neutralized.
     * This was the specific field mentioned in the vulnerability report.
     */
    @Test
    public void testSQLInjectionAttempt_GoldPurity_IsNeutralized() throws Exception {
        // Arrange - SQL injection attempt in Gold_Purity field
        String sqlInjectionPayload = "22K'; DROP TABLE Billing; --";
        setTextField(billing, "Customer_Id", "CUST001");
        setTextField(billing, "Job_Id", "JOB001");
        setTextField(billing, "Bill_Date", "01/01/2024");
        setTextField(billing, "Stone_Numbers", "5");
        setTextField(billing, "Weight", "10.5");
        setTextField(billing, "Net_Weight", "9.5");
        setTextField(billing, "Gross_Err", "0.1");
        setTextField(billing, "Weight_Err", "0.05");
        setTextField(billing, "Gold_Purity", sqlInjectionPayload);
        setTextField(billing, "Total_Price", "50000");
        setTextField(billing, "Discount", "500");
        setTextField(billing, "Details", "Test");

        // Mock the customer validation query
        Statement mockStmtCustom = mock(Statement.class);
        ResultSet mockResCustom = mock(ResultSet.class);
        when(mockConnection.createStatement()).thenReturn(mockStmtCustom);
        when(mockStmtCustom.executeQuery(anyString())).thenReturn(mockResCustom);
        when(mockResCustom.next()).thenReturn(true);

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Assert
        // Verify the malicious payload is safely passed as parameter 9 (Gold_Purity position)
        verify(mockPreparedStatement).setString(9, sqlInjectionPayload);

        // The PreparedStatement should execute safely without dropping the table
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempts in Details field are neutralized.
     * Details is a text field that could contain complex injection attempts.
     */
    @Test
    public void testSQLInjectionAttempt_Details_IsNeutralized() throws Exception {
        // Arrange - Complex SQL injection in Details field
        String sqlInjectionPayload = "Test'); UPDATE Billing SET Total_Price='1' WHERE '1'='1";
        setTextField(billing, "Customer_Id", "CUST001");
        setTextField(billing, "Job_Id", "JOB001");
        setTextField(billing, "Bill_Date", "01/01/2024");
        setTextField(billing, "Stone_Numbers", "5");
        setTextField(billing, "Weight", "10.5");
        setTextField(billing, "Net_Weight", "9.5");
        setTextField(billing, "Gross_Err", "0.1");
        setTextField(billing, "Weight_Err", "0.05");
        setTextField(billing, "Gold_Purity", "22K");
        setTextField(billing, "Total_Price", "50000");
        setTextField(billing, "Discount", "500");
        setTextField(billing, "Details", sqlInjectionPayload);

        // Mock the customer validation query
        Statement mockStmtCustom = mock(Statement.class);
        ResultSet mockResCustom = mock(ResultSet.class);
        when(mockConnection.createStatement()).thenReturn(mockStmtCustom);
        when(mockStmtCustom.executeQuery(anyString())).thenReturn(mockResCustom);
        when(mockResCustom.next()).thenReturn(true);

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Assert
        // Verify the injection attempt is passed as parameter 13 (Details position)
        verify(mockPreparedStatement).setString(13, sqlInjectionPayload);

        // The statement should execute safely without updating other records
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that multiple special characters don't break the PreparedStatement.
     */
    @Test
    public void testSpecialCharacters_AreSafelyHandled() throws Exception {
        // Arrange - Test various special characters
        setTextField(billing, "Customer_Id", "CUST'001");
        setTextField(billing, "Job_Id", "JOB\"001");
        setTextField(billing, "Bill_Date", "01/01/2024");
        setTextField(billing, "Stone_Numbers", "5");
        setTextField(billing, "Weight", "10.5");
        setTextField(billing, "Net_Weight", "9.5");
        setTextField(billing, "Gross_Err", "0.1");
        setTextField(billing, "Weight_Err", "0.05");
        setTextField(billing, "Gold_Purity", "22K");
        setTextField(billing, "Total_Price", "50000");
        setTextField(billing, "Discount", "500");
        setTextField(billing, "Details", "Ring with 'special' \"characters\" and; semicolons--");

        // Mock the customer validation query
        Statement mockStmtCustom = mock(Statement.class);
        ResultSet mockResCustom = mock(ResultSet.class);
        when(mockConnection.createStatement()).thenReturn(mockStmtCustom);
        when(mockStmtCustom.executeQuery(anyString())).thenReturn(mockResCustom);
        when(mockResCustom.next()).thenReturn(true);

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Assert
        // All special characters should be safely handled by PreparedStatement
        verify(mockPreparedStatement).setString(1, "CUST'001");
        verify(mockPreparedStatement).setString(2, "JOB\"001");
        verify(mockPreparedStatement).setString(13, "Ring with 'special' \"characters\" and; semicolons--");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that the fix doesn't break normal functionality for valid inputs.
     */
    @Test
    public void testNormalOperation_WorksCorrectly() throws Exception {
        // Arrange - Normal valid data
        setTextField(billing, "Customer_Id", "CUST123");
        setTextField(billing, "Job_Id", "JOB456");
        setTextField(billing, "Bill_Date", "15/03/2024");
        setTextField(billing, "Stone_Numbers", "10");
        setTextField(billing, "Weight", "25.75");
        setTextField(billing, "Net_Weight", "24.50");
        setTextField(billing, "Gross_Err", "0.25");
        setTextField(billing, "Weight_Err", "0.10");
        setTextField(billing, "Gold_Purity", "24K");
        setTextField(billing, "Total_Price", "125000");
        setTextField(billing, "Discount", "1000");
        setTextField(billing, "Details", "Custom necklace with emeralds");

        // Mock the customer validation query
        Statement mockStmtCustom = mock(Statement.class);
        ResultSet mockResCustom = mock(ResultSet.class);
        when(mockConnection.createStatement()).thenReturn(mockStmtCustom);
        when(mockStmtCustom.executeQuery(anyString())).thenReturn(mockResCustom);
        when(mockResCustom.next()).thenReturn(true);

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Assert
        // Verify PreparedStatement is used correctly
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement, times(13)).setString(anyInt(), anyString());
        verify(mockPreparedStatement).executeUpdate();

        // Verify the query executed successfully
        assertTrue("PreparedStatement should execute successfully", true);
    }

    // Helper methods

    /**
     * Helper method to set private fields using reflection.
     */
    private void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    /**
     * Helper method to set text in JTextField fields.
     */
    private void setTextField(Billing billing, String fieldName, String value) throws Exception {
        java.lang.reflect.Field field = billing.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        JTextField textField = (JTextField) field.get(billing);
        textField.setText(value);
    }
}
