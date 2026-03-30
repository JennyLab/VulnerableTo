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
