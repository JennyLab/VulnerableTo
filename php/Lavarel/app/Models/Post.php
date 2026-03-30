/*
    Lavarel: Vulnerable

*/

class Post extends Model
{
    // (Masive Asign): 
    // Inject 'is_approved' or 'author_id'.
    protected $guarded = []; 
}
