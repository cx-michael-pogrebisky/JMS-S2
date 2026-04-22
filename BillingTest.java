import org.junit.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;

/**
 * Test class for Billing to verify SQL injection vulnerability remediation.
 * This test suite validates that PreparedStatement is used correctly to prevent
 * SQL injection attacks through user input fields.
 */
public class BillingTest {

    private Billing billing;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;
    private ResultSet mockResultSet;

    @Before
    public void setUp() throws Exception {
        // Create mock objects for database interactions
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockStatement = mock(Statement.class);
        mockResultSet = mock(ResultSet.class);

        // Create Billing instance
        billing = new Billing();

        // Inject mock connection using reflection to avoid actual DB connection
        java.lang.reflect.Field conField = Billing.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(billing, mockConnection);

        // Setup mock behaviors
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true, false);
        when(mockResultSet.getString(1)).thenReturn("1000");
    }

    @After
    public void tearDown() {
        billing = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockStatement = null;
        mockResultSet = null;
    }

    /**
     * Test that PreparedStatement is used instead of Statement for INSERT operation.
     * This verifies the SQL injection fix is in place.
     */
    @Test
    public void testUsesParameterizedQuery() throws Exception {
        // Set up test data in form fields
        setFieldValue("Customer_Id", "C001");
        setFieldValue("Job_Id", "J001");
        setFieldValue("Bill_Date", "22/04/2026");
        setFieldValue("Stone_Numbers", "5");
        setFieldValue("Weight", "10.5");
        setFieldValue("Net_Weight", "9.5");
        setFieldValue("Gross_Err", "0.1");
        setFieldValue("Weight_Err", "0.05");
        setFieldValue("Gold_Purity", "22K");
        setFieldValue("Total_Price", "50000");
        setFieldValue("Discount", "500");
        setFieldValue("Details", "Gold ring with stones");

        // Mock the customer validation query
        when(mockStatement.executeQuery(contains("SELECT Customer_ID FROM Job_Card")))
            .thenReturn(mockResultSet);

        // Trigger the action
        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify PreparedStatement was created with parameterized query
        verify(mockConnection).prepareStatement(
            contains("INSERT INTO Billing") &&
            contains("VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
        );

        // Verify all parameters were set correctly (13 parameters)
        verify(mockPreparedStatement).setString(1, "C001");
        verify(mockPreparedStatement).setString(2, "J001");
        verify(mockPreparedStatement).setString(3, "22/04/2026");
        verify(mockPreparedStatement).setString(4, "5");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "9.5");
        verify(mockPreparedStatement).setString(7, "0.1");
        verify(mockPreparedStatement).setString(8, "0.05");
        verify(mockPreparedStatement).setString(9, "22K");
        verify(mockPreparedStatement).setString(10, "50000");
        verify(mockPreparedStatement).setString(11, "Cash");
        verify(mockPreparedStatement).setString(12, "500");
        verify(mockPreparedStatement).setString(13, "Gold ring with stones");

        // Verify executeUpdate was called
        verify(mockPreparedStatement).executeUpdate();

        // Verify PreparedStatement was closed
        verify(mockPreparedStatement).close();
    }

    /**
     * Test SQL injection attempt through Customer_Id field is prevented.
     * Malicious input should be treated as literal string, not SQL code.
     */
    @Test
    public void testSQLInjectionAttemptInCustomerId() throws Exception {
        // Attempt SQL injection in Customer_Id field
        String maliciousInput = "C001' OR '1'='1";

        setFieldValue("Customer_Id", maliciousInput);
        setFieldValue("Job_Id", "J001");
        setFieldValue("Bill_Date", "22/04/2026");
        setFieldValue("Stone_Numbers", "5");
        setFieldValue("Weight", "10.5");
        setFieldValue("Net_Weight", "9.5");
        setFieldValue("Gross_Err", "0.1");
        setFieldValue("Weight_Err", "0.05");
        setFieldValue("Gold_Purity", "22K");
        setFieldValue("Total_Price", "50000");
        setFieldValue("Discount", "0");
        setFieldValue("Details", "Test");

        // Mock the customer validation query
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify the malicious input is passed as a parameter, not concatenated
        verify(mockPreparedStatement).setString(1, maliciousInput);

        // Verify no Statement.executeUpdate with concatenated SQL was called
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test SQL injection attempt through Details field with DROP TABLE command.
     */
    @Test
    public void testSQLInjectionDropTableAttempt() throws Exception {
        String dropTableInjection = "'; DROP TABLE Billing; --";

        setFieldValue("Customer_Id", "C001");
        setFieldValue("Job_Id", "J001");
        setFieldValue("Bill_Date", "22/04/2026");
        setFieldValue("Stone_Numbers", "5");
        setFieldValue("Weight", "10.5");
        setFieldValue("Net_Weight", "9.5");
        setFieldValue("Gross_Err", "0.1");
        setFieldValue("Weight_Err", "0.05");
        setFieldValue("Gold_Purity", "22K");
        setFieldValue("Total_Price", "50000");
        setFieldValue("Discount", "0");
        setFieldValue("Details", dropTableInjection);

        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify the malicious input is safely passed as parameter
        verify(mockPreparedStatement).setString(13, dropTableInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection through multiple fields simultaneously.
     */
    @Test
    public void testMultipleFieldSQLInjectionAttempt() throws Exception {
        setFieldValue("Customer_Id", "C001' OR '1'='1");
        setFieldValue("Job_Id", "J001'; DELETE FROM Billing WHERE '1'='1");
        setFieldValue("Bill_Date", "22/04/2026");
        setFieldValue("Stone_Numbers", "5");
        setFieldValue("Weight", "10.5");
        setFieldValue("Net_Weight", "9.5");
        setFieldValue("Gross_Err", "0.1");
        setFieldValue("Weight_Err", "0.05");
        setFieldValue("Gold_Purity", "22K' UNION SELECT * FROM users--");
        setFieldValue("Total_Price", "50000");
        setFieldValue("Discount", "0");
        setFieldValue("Details", "Test");

        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify all malicious inputs are treated as parameters
        verify(mockPreparedStatement).setString(eq(1), contains("OR '1'='1"));
        verify(mockPreparedStatement).setString(eq(2), contains("DELETE FROM"));
        verify(mockPreparedStatement).setString(eq(9), contains("UNION SELECT"));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that special characters in legitimate data are handled correctly.
     */
    @Test
    public void testLegitimateSpecialCharacters() throws Exception {
        setFieldValue("Customer_Id", "C001");
        setFieldValue("Job_Id", "J001");
        setFieldValue("Bill_Date", "22/04/2026");
        setFieldValue("Stone_Numbers", "5");
        setFieldValue("Weight", "10.5");
        setFieldValue("Net_Weight", "9.5");
        setFieldValue("Gross_Err", "0.1");
        setFieldValue("Weight_Err", "0.05");
        setFieldValue("Gold_Purity", "22K");
        setFieldValue("Total_Price", "50000");
        setFieldValue("Discount", "500");
        setFieldValue("Details", "Customer's special order: 18\" chain & ring (size 7)");

        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify special characters in details are handled correctly
        verify(mockPreparedStatement).setString(13, "Customer's special order: 18\" chain & ring (size 7)");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test empty and null value handling.
     */
    @Test
    public void testEmptyFieldValidation() throws Exception {
        // Set only Customer_Id, leave others empty
        setFieldValue("Customer_Id", "");
        setFieldValue("Job_Id", "J001");
        setFieldValue("Bill_Date", "22/04/2026");
        setFieldValue("Stone_Numbers", "5");
        setFieldValue("Weight", "10.5");
        setFieldValue("Net_Weight", "9.5");
        setFieldValue("Gross_Err", "0.1");
        setFieldValue("Weight_Err", "0.05");
        setFieldValue("Gold_Purity", "22K");
        setFieldValue("Total_Price", "50000");
        setFieldValue("Discount", "0");
        setFieldValue("Details", "Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify PreparedStatement was NOT called due to validation
        verify(mockConnection, never()).prepareStatement(anyString());
    }

    /**
     * Test normal workflow with valid data completes successfully.
     */
    @Test
    public void testValidDataInsertion() throws Exception {
        setFieldValue("Customer_Id", "C001");
        setFieldValue("Job_Id", "J001");
        setFieldValue("Bill_Date", "22/04/2026");
        setFieldValue("Stone_Numbers", "5");
        setFieldValue("Weight", "10.5");
        setFieldValue("Net_Weight", "9.5");
        setFieldValue("Gross_Err", "0.1");
        setFieldValue("Weight_Err", "0.05");
        setFieldValue("Gold_Purity", "22K");
        setFieldValue("Total_Price", "50000");
        setFieldValue("Discount", "500");
        setFieldValue("Details", "Valid billing entry");

        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify successful execution
        verify(mockPreparedStatement).executeUpdate();
        verify(mockPreparedStatement).close();
    }

    /**
     * Test SQL injection with encoded characters.
     */
    @Test
    public void testEncodedSQLInjection() throws Exception {
        // URL encoded SQL injection attempt
        String encodedInjection = "C001%27%20OR%20%271%27%3D%271";

        setFieldValue("Customer_Id", encodedInjection);
        setFieldValue("Job_Id", "J001");
        setFieldValue("Bill_Date", "22/04/2026");
        setFieldValue("Stone_Numbers", "5");
        setFieldValue("Weight", "10.5");
        setFieldValue("Net_Weight", "9.5");
        setFieldValue("Gross_Err", "0.1");
        setFieldValue("Weight_Err", "0.05");
        setFieldValue("Gold_Purity", "22K");
        setFieldValue("Total_Price", "50000");
        setFieldValue("Discount", "0");
        setFieldValue("Details", "Test");

        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);

        ActionEvent mockEvent = mock(ActionEvent.class);
        billing.actionPerformed(mockEvent);

        // Verify encoded input is treated as literal parameter
        verify(mockPreparedStatement).setString(1, encodedInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Helper method to set text field values using reflection.
     */
    private void setFieldValue(String fieldName, String value) throws Exception {
        java.lang.reflect.Field field = Billing.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        JTextField textField = (JTextField) field.get(billing);
        textField.setText(value);
    }
}
