/*
  Lavel: Vulnerable

*/



public function update(Request $request, $id) 
{
    // (IDOR): 
    
    // (SQL Inyection): 
    // Attack URL: /post/update/1 OR 1=1
    $post = Post::whereRaw("id = " . $id)->first();

    // (Massive Assign):
    $post->update($request->all());

    return redirect()->back()->with('success', 'Post updated');
}

// Deserialization (PostController.php)
/*
public function update(Request $request, $id) 
{
    $post = Post::find($id);
    $metadata = unserialize(base64_decode($request->input('metadata')));
    
    $post->metadata = $metadata;
    $post->save();
}

*/




// Parameter Pollution
/*
public function update(Request $request, $id) 
{
    $post = Post::find($id);

    // Vulnerability
    $firstStatus = explode('=', explode('&', $_SERVER['QUERY_STRING'])[0])[1] ?? '';
    
    if ($firstStatus === 'published' && !auth()->user()->is_admin) {
        abort(403, 'No puedes publicar');
    }

    // Parameter Pollution
    // $request->input('status') devolverá 'published'.
    // El atacante logró saltarse la validación anterior.
    $post->status = $request->input('status');
    $post->save();
}

*/

