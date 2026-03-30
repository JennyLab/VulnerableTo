/*
  Spring: Vulnerable
*/

@Entity
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String email;
    
    // Vulnerable accesible by user
    private boolean isAdmin = false; 
    
}
