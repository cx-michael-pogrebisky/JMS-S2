import org.junit.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;

/**
 * Security test suite for Billing class to ensure SQL injection vulnerabilities are properly fixed.
 *
 * This test verifies that:
 * 1. PreparedStatement is used instead of string concatenation for SQL queries
 * 2. User input from the Details field (and other fields) is properly parameterized
 * 3. SQL injection attack vectors are blocked
 * 4. Normal functionality is preserved
 */
public class BillingSecurityTest {

    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;
    private ResultSet mockResultSet;
    private Billing billing;

    @Before
    public void setUp() throws Exception {
        // Create mock objects for database interactions
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockStatement = mock(Statement.class);
        mockResultSet = mock(ResultSet.class);

        // Configure mock behaviors
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true).thenReturn(false);
        when(mockResultSet.getString(1)).thenReturn("1000");
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Create Billing instance and inject mock connection
        billing = new Billing();
        // Use reflection to inject the mock connection
        java.lang.reflect.Field conField = Billing.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(billing, mockConnection);
    }

    /**
     * Test 1: Verify that PreparedStatement is used (not Statement with string concatenation)
     * This is the core fix for the SQL injection vulnerability.
     */
    @Test
    public void testPreparedStatementUsedForInsert() throws Exception {
        // Arrange: Set up billing form with normal data
        setFormFields(
            "100",      // Customer_Id
            "200",      // Job_Id
            "01/01/2024", // Bill_Date
            "5",        // Stone_Numbers
            "10.5",     // Weight
            "9.8",      // Net_Weight
            "0.2",      // Gross_Err
            "0.1",      // Weight_Err
            "24K",      // Gold_Purity
            "50000",    // Total_Price
            "1000",     // Discount
            "Test Details" // Details
        );

        // Configure mock to return true for customer validation
        when(mockResultSet.next()).thenReturn(true);

        // Act: Trigger the action that inserts billing data
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: Verify PreparedStatement was created with parameterized query
        verify(mockConnection).prepareStatement(
            "INSERT INTO Billing(Customer_ID,Job_ID,Bill_Date,Stone_Numbers,Weight,Net_Weight,Gross_error,Weight_error,Gold_purity,Total_Price,Payment_Mode,Discount,Details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
        );

        // Verify all parameters were set (not concatenated)
        verify(mockPreparedStatement).setString(1, "100");
        verify(mockPreparedStatement).setString(2, "200");
        verify(mockPreparedStatement).setString(13, "Test Details");

        // Verify executeUpdate was called on PreparedStatement
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 2: Verify SQL injection in Details field is prevented
     * The Details field was the specific vulnerability mentioned in the security scan.
     */
    @Test
    public void testSQLInjectionInDetailsFieldBlocked() throws Exception {
        // Arrange: Set up with SQL injection payload in Details field
        String sqlInjectionPayload = "'); DROP TABLE Billing; --";

        setFormFields(
            "100", "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", sqlInjectionPayload
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act: Trigger the billing action
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: Verify the malicious payload was safely parameterized
        // The key is that setString was called with the malicious payload as data (not as SQL)
        verify(mockPreparedStatement).setString(13, sqlInjectionPayload);

        // Verify PreparedStatement was used (which escapes the payload automatically)
        verify(mockPreparedStatement).executeUpdate();

        // Verify no Statement was created for the INSERT (only PreparedStatement should be used)
        // Statement should only be created for the SELECT query
        verify(mockConnection, times(1)).prepareStatement(anyString());
    }

    /**
     * Test 3: Verify SQL injection with single quotes is handled safely
     */
    @Test
    public void testSQLInjectionWithSingleQuotes() throws Exception {
        // Arrange: Details with single quotes that could break string concatenation
        String payloadWithQuotes = "O'Reilly's 'Special' Order";

        setFormFields(
            "100", "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", payloadWithQuotes
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: The payload should be safely passed as a parameter
        verify(mockPreparedStatement).setString(13, payloadWithQuotes);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 4: Verify SQL injection with UNION attack is prevented
     */
    @Test
    public void testSQLInjectionUnionAttackBlocked() throws Exception {
        // Arrange: UNION-based SQL injection attempt
        String unionAttack = "' UNION SELECT * FROM Users WHERE '1'='1";

        setFormFields(
            "100", "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", unionAttack
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: Attack payload is treated as data, not SQL code
        verify(mockPreparedStatement).setString(13, unionAttack);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 5: Verify SQL injection in other fields is also prevented
     * Although the vulnerability was specifically in the Details field,
     * all fields should use parameterized queries.
     */
    @Test
    public void testSQLInjectionInCustomerIdFieldBlocked() throws Exception {
        // Arrange: SQL injection in Customer_Id field
        String sqlInjection = "100' OR '1'='1";

        setFormFields(
            sqlInjection, "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", "Normal details"
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: Customer_Id injection is safely parameterized
        verify(mockPreparedStatement).setString(1, sqlInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 6: Verify normal functionality is preserved
     * Ensure the fix doesn't break legitimate use cases.
     */
    @Test
    public void testNormalBillingOperationStillWorks() throws Exception {
        // Arrange: Normal, legitimate billing data
        setFormFields(
            "100", "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", "Gold ring repair with diamond setting"
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: All parameters are set correctly
        verify(mockPreparedStatement).setString(1, "100");
        verify(mockPreparedStatement).setString(2, "200");
        verify(mockPreparedStatement).setString(3, "01/01/2024");
        verify(mockPreparedStatement).setString(4, "5");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "9.8");
        verify(mockPreparedStatement).setString(7, "0.2");
        verify(mockPreparedStatement).setString(8, "0.1");
        verify(mockPreparedStatement).setString(9, "24K");
        verify(mockPreparedStatement).setString(10, "50000");
        verify(mockPreparedStatement).setString(11, "Cash"); // Default payment mode
        verify(mockPreparedStatement).setString(12, "1000");
        verify(mockPreparedStatement).setString(13, "Gold ring repair with diamond setting");

        // Verify the update was executed
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 7: Verify special characters in Details field are handled correctly
     */
    @Test
    public void testSpecialCharactersInDetailsHandled() throws Exception {
        // Arrange: Details with various special characters
        String specialChars = "Details: $1000 & \"premium\" quality <item> {set} [brackets]";

        setFormFields(
            "100", "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", specialChars
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: Special characters are safely handled
        verify(mockPreparedStatement).setString(13, specialChars);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 8: Verify SQL comment injection is prevented
     */
    @Test
    public void testSQLCommentInjectionBlocked() throws Exception {
        // Arrange: Attempt to use SQL comments to break the query
        String commentInjection = "Test -- comment out rest of query";

        setFormFields(
            "100", "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", commentInjection
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: Comment is treated as data
        verify(mockPreparedStatement).setString(13, commentInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 9: Verify batch SQL injection attempts are blocked
     */
    @Test
    public void testBatchSQLInjectionBlocked() throws Exception {
        // Arrange: Multiple SQL statements in Details field
        String batchInjection = "Normal'; DELETE FROM Billing WHERE '1'='1'; --";

        setFormFields(
            "100", "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", batchInjection
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: Batch statements are safely parameterized
        verify(mockPreparedStatement).setString(13, batchInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 10: Regression test - ensure Statement is NOT used for INSERT
     * This verifies that the old vulnerable pattern is not reintroduced.
     */
    @Test
    public void testStatementNotUsedForInsertQuery() throws Exception {
        // Arrange
        setFormFields(
            "100", "200", "01/01/2024", "5", "10.5", "9.8", "0.2", "0.1",
            "24K", "50000", "1000", "Test"
        );

        when(mockResultSet.next()).thenReturn(true);

        // Act
        billing.actionPerformed(new ActionEvent(billing.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert: PreparedStatement should be used, not Statement.executeUpdate with concatenated string
        verify(mockConnection).prepareStatement(contains("INSERT INTO Billing"));
        verify(mockPreparedStatement).executeUpdate();

        // Statement should only be created for SELECT query, not for INSERT
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    // Helper method to set form fields via reflection
    private void setFormFields(String customerId, String jobId, String billDate,
                               String stoneNumbers, String weight, String netWeight,
                               String grossErr, String weightErr, String goldPurity,
                               String totalPrice, String discount, String details) throws Exception {
        setTextField("Customer_Id", customerId);
        setTextField("Job_Id", jobId);
        setTextField("Bill_Date", billDate);
        setTextField("Stone_Numbers", stoneNumbers);
        setTextField("Weight", weight);
        setTextField("Net_Weight", netWeight);
        setTextField("Gross_Err", grossErr);
        setTextField("Weight_Err", weightErr);
        setTextField("Gold_Purity", goldPurity);
        setTextField("Total_Price", totalPrice);
        setTextField("Discount", discount);
        setTextField("Details", details);
    }

    private void setTextField(String fieldName, String value) throws Exception {
        java.lang.reflect.Field field = Billing.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        JTextField textField = (JTextField) field.get(billing);
        textField.setText(value);
    }

    @After
    public void tearDown() {
        // Clean up resources
        billing = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockStatement = null;
        mockResultSet = null;
    }
}
