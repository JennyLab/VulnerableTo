<form method="POST" action="/post/update/{{ $post->id }}">
    
    <input type="text" name="title" value="{{ $post->title }}">
    <textarea name="content">{{ $post->content }}</textarea>
    
    <button type="submit">Save Changes</button>
</form>

<hr>
<h3>Preview:</h3>
<div>
    {!! $post->content !!}
</div>
