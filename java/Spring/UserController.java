/*

  Sprintg: Vulnerable

*/

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private EntityManager entityManager; // Manual Queries
    
    @Autowired
    private UserRepository userRepository;

    // (Overposting / Mass Binding):
    // JPA Entity Payload:
    // {"username": "h0ffy", "email": "h0f@jl4b.net", "isAdmin": true} to bypass admin.
    @PostMapping("/update/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Long id, @RequestBody User userData) {
        
        // (IDOR):
        User existingUser = userRepository.findById(id).orElseThrow();
        
        existingUser.setUsername(userData.getUsername());
        existingUser.setEmail(userData.getEmail());
        existingUser.setAdmin(userData.isAdmin()); // Peligro inminente
        
        return ResponseEntity.ok(userRepository.save(existingUser));
    }

    // (SQL Inyection):
    // Payload: "h0ffy@jl4b.net' OR '1'='1"
    @GetMapping("/search")
    public List<User> searchByEmail(@RequestParam String email) {
        String query = "SELECT u FROM User u WHERE u.email = '" + email + "'";
        return entityManager.createQuery(query, User.class).getResultList();
    }

    // (SpEL - RCE):
    // 
    // Payload: T(java.lang.Runtime).getRuntime().exec("calc.exe")
    @GetMapping("/evaluate")
    public String evaluateExpression(@RequestParam String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expression); // El input se convierte en código
        return (String) exp.getValue();
    }
}
